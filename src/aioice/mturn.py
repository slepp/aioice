"""
Microsoft TURN (MS-TURN) client implementation.

MS-TURN uses the old STUN format (RFC 3489 / IETFDRAFT-STUN-02):
- Header: message type (2 bytes) + length (2 bytes) + transaction ID (16 bytes)
- NO magic cookie in header (unlike RFC 5389 which has 0x2112A442)
- MAGIC-COOKIE attribute (0x000F, value 0x72c64bc6) must be first attribute

This is distinct from standard TURN (RFC 5766) and is used by Microsoft Teams
for relaying ICE candidates through the Microsoft relay network.
"""

import asyncio
import hashlib
import hmac
import ipaddress
import logging
import os
import socket
import struct
from struct import pack, unpack
from typing import Optional

logger = logging.getLogger(__name__)

# MS-TURN header format: type(2) + length(2) + transaction_id(16)
MTURN_HEADER_LENGTH = 20
MTURN_TXN_ID_LENGTH = 16
MTURN_INTEGRITY_LENGTH = 24  # 4 (attr header) + 20 (sha1)

# The magic cookie value that goes in the MAGIC-COOKIE attribute (not the header)
MTURN_MAGIC_COOKIE_VALUE = 0x72C64BC6

# MS-TURN message types (old STUN encoding: response = request | 0x0100, error = request | 0x0110)
MTURN_METHOD_ALLOCATE = 0x0003
MTURN_METHOD_SEND = 0x0004
MTURN_METHOD_SET_ACTIVE_DEST = 0x0006

MTURN_CLASS_REQUEST = 0x0000
MTURN_CLASS_RESPONSE = 0x0100
MTURN_CLASS_ERROR = 0x0110
MTURN_CLASS_INDICATION = 0x0010

# Full message types
MTURN_ALLOCATE_REQUEST = MTURN_METHOD_ALLOCATE | MTURN_CLASS_REQUEST      # 0x0003
MTURN_ALLOCATE_RESPONSE = MTURN_METHOD_ALLOCATE | MTURN_CLASS_RESPONSE    # 0x0103
MTURN_ALLOCATE_ERROR = MTURN_METHOD_ALLOCATE | MTURN_CLASS_ERROR           # 0x0113
MTURN_SEND_REQUEST = MTURN_METHOD_SEND | MTURN_CLASS_REQUEST               # 0x0004
MTURN_SEND_RESPONSE = MTURN_METHOD_SEND | MTURN_CLASS_RESPONSE             # 0x0104
MTURN_DATA_INDICATION = MTURN_METHOD_SEND | MTURN_CLASS_INDICATION         # 0x0014  (0x0004 | 0x0010)
MTURN_SET_ACTIVE_DEST_REQUEST = MTURN_METHOD_SET_ACTIVE_DEST | MTURN_CLASS_REQUEST   # 0x0006
MTURN_SET_ACTIVE_DEST_RESPONSE = MTURN_METHOD_SET_ACTIVE_DEST | MTURN_CLASS_RESPONSE # 0x0106

# MS-TURN attribute type codes
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_DESTINATION_ADDRESS = 0x0002     # Used in Send requests (target peer)
ATTR_REMOTE_ADDRESS = 0x0004          # Used in Data indications (source peer)
ATTR_USERNAME = 0x0006
ATTR_MESSAGE_INTEGRITY = 0x0008
ATTR_ERROR_CODE = 0x0009
ATTR_LIFETIME = 0x000D
ATTR_MAGIC_COOKIE = 0x000F            # MS-TURN specific, value must be 0x72c64bc6
ATTR_BANDWIDTH = 0x0010               # Required in ALLOCATE requests
ATTR_DATA = 0x0013
ATTR_REALM = 0x0014
ATTR_NONCE = 0x0015
ATTR_MS_VERSION = 0x8008
ATTR_XOR_MAPPED_ADDRESS = 0x8020      # Old non-standard XOR-MAPPED-ADDRESS
ATTR_MS_SEQUENCE_NUMBER = 0x8050

IPV4_FAMILY = 0x01
IPV6_FAMILY = 0x02

# Retry settings
RETRY_MAX = 6
RETRY_RTO = 0.5

DEFAULT_ALLOCATION_LIFETIME = 600


def _random_txn_id() -> bytes:
    """Generate a 16-byte MS-TURN transaction ID."""
    return os.urandom(MTURN_TXN_ID_LENGTH)


def _pad(length: int) -> int:
    """Return number of padding bytes needed for 4-byte alignment."""
    rest = length % 4
    return 0 if rest == 0 else 4 - rest


def _pack_address(ip: str, port: int) -> bytes:
    """Pack an address as STUN MAPPED-ADDRESS format (family + port + addr)."""
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv4Address):
        return pack("!BBH4s", 0, IPV4_FAMILY, port, addr.packed)
    else:
        return pack("!BBH16s", 0, IPV6_FAMILY, port, addr.packed)


def _unpack_address(data: bytes) -> tuple[str, int]:
    """Unpack a STUN-format address attribute."""
    if len(data) < 4:
        raise ValueError("Address attribute too short")
    _, family = unpack("!BB", data[0:2])
    port = unpack("!H", data[2:4])[0]
    if family == IPV4_FAMILY:
        if len(data) < 8:
            raise ValueError("IPv4 address too short")
        return str(ipaddress.IPv4Address(data[4:8])), port
    elif family == IPV6_FAMILY:
        if len(data) < 20:
            raise ValueError("IPv6 address too short")
        return str(ipaddress.IPv6Address(data[4:20])), port
    else:
        raise ValueError(f"Unknown address family: {family}")


def _unpack_xor_address(data: bytes) -> tuple[str, int]:
    """Unpack an old-style XOR-MAPPED-ADDRESS (XOR with magic cookie 0x2112A442)."""
    if len(data) < 4:
        raise ValueError("XOR address attribute too short")
    _, family = unpack("!BB", data[0:2])
    xport = unpack("!H", data[2:4])[0]
    port = xport ^ (MTURN_MAGIC_COOKIE_VALUE >> 16)
    if family == IPV4_FAMILY:
        if len(data) < 8:
            raise ValueError("IPv4 XOR address too short")
        xip = unpack("!I", data[4:8])[0]
        ip = xip ^ MTURN_MAGIC_COOKIE_VALUE
        return str(ipaddress.IPv4Address(ip)), port
    elif family == IPV6_FAMILY:
        if len(data) < 20:
            raise ValueError("IPv6 XOR address too short")
        # XOR first 4 bytes with magic cookie
        xip = bytearray(data[4:20])
        mc = pack("!I", MTURN_MAGIC_COOKIE_VALUE)
        for i in range(4):
            xip[i] ^= mc[i]
        return str(ipaddress.IPv6Address(bytes(xip))), port
    else:
        raise ValueError(f"Unknown address family: {family}")


def _unpack_error_code(data: bytes) -> tuple[int, str]:
    """Unpack STUN ERROR-CODE attribute."""
    if len(data) < 4:
        raise ValueError("Error code too short")
    _, high, low = unpack("!HBB", data[0:4])
    reason = data[4:].decode("utf-8", errors="replace")
    return high * 100 + low, reason


def _make_integrity_key(username: str, realm: str, password: str) -> bytes:
    """Compute TURN long-term credential key: MD5(username:realm:password)."""
    return hashlib.md5(f"{username}:{realm}:{password}".encode("utf-8")).digest()


class MTurnMessage:
    """
    Represents a MS-TURN message in old STUN (RFC 3489) format.

    Header: type(2) + length(2) + transaction_id(16) = 20 bytes total.
    Attributes are stored as a list of (type, value_bytes) pairs to preserve order
    and allow duplicates. The MAGIC-COOKIE attribute must be first.
    """

    def __init__(
        self,
        msg_type: int,
        transaction_id: Optional[bytes] = None,
    ) -> None:
        self.msg_type = msg_type
        self.transaction_id = transaction_id or _random_txn_id()
        # List of (attr_type, attr_value_bytes) to preserve insertion order
        self._attrs: list[tuple[int, bytes]] = []

    def add_attr(self, attr_type: int, value: bytes) -> None:
        self._attrs.append((attr_type, value))

    def get_attr(self, attr_type: int) -> Optional[bytes]:
        for t, v in self._attrs:
            if t == attr_type:
                return v
        return None

    def add_magic_cookie(self) -> None:
        """Prepend the required MS-TURN magic cookie attribute."""
        self._attrs.insert(0, (ATTR_MAGIC_COOKIE, pack("!I", MTURN_MAGIC_COOKIE_VALUE)))

    def _body_bytes(self) -> bytes:
        """Serialize all attributes to bytes."""
        out = b""
        for attr_type, value in self._attrs:
            attr_len = len(value)
            pad = _pad(attr_len)
            out += pack("!HH", attr_type, attr_len) + value + bytes(pad)
        return out

    def __bytes__(self) -> bytes:
        body = self._body_bytes()
        return pack("!HH16s", self.msg_type, len(body), self.transaction_id) + body

    def add_message_integrity(self, key: bytes) -> None:
        """
        Append MESSAGE-INTEGRITY over the current message content.
        The length in the header is set to include the MI attribute.
        """
        # Build message as-if MI were already appended (with the final length)
        body_so_far = self._body_bytes()
        # The length field will be: current body + 4 (attr header) + 20 (sha1) = current + 24
        future_length = len(body_so_far) + MTURN_INTEGRITY_LENGTH
        check_data = (
            pack("!HH16s", self.msg_type, future_length, self.transaction_id)
            + body_so_far
        )
        digest = hmac.new(key, check_data, "sha1").digest()
        self._attrs.append((ATTR_MESSAGE_INTEGRITY, digest))

    @property
    def is_response(self) -> bool:
        return (self.msg_type & 0x0100) != 0 and (self.msg_type & 0x0010) == 0

    @property
    def is_error(self) -> bool:
        return (self.msg_type & 0x0110) == 0x0110

    @property
    def is_indication(self) -> bool:
        return (self.msg_type & 0x0110) == 0x0010

    @property
    def method(self) -> int:
        return self.msg_type & ~0x0110

    def __repr__(self) -> str:
        return f"MTurnMessage(type=0x{self.msg_type:04x}, txn={self.transaction_id.hex()})"


def parse_mturn_message(data: bytes) -> MTurnMessage:
    """Parse a raw MS-TURN/old-STUN message."""
    if len(data) < MTURN_HEADER_LENGTH:
        raise ValueError(f"MS-TURN message too short: {len(data)} bytes")

    msg_type, body_length, txn_id = unpack("!HH16s", data[:MTURN_HEADER_LENGTH])
    if len(data) < MTURN_HEADER_LENGTH + body_length:
        raise ValueError("MS-TURN message truncated")

    msg = MTurnMessage(msg_type, txn_id)

    pos = MTURN_HEADER_LENGTH
    end = MTURN_HEADER_LENGTH + body_length
    while pos + 4 <= end:
        attr_type, attr_len = unpack("!HH", data[pos:pos + 4])
        attr_val = data[pos + 4: pos + 4 + attr_len]
        msg._attrs.append((attr_type, attr_val))
        pos += 4 + attr_len + _pad(attr_len)

    return msg


def _parse_attrs(msg: MTurnMessage) -> dict:
    """Parse well-known attributes from an MTurnMessage into a dict."""
    result: dict = {}
    for attr_type, val in msg._attrs:
        if attr_type == ATTR_MAPPED_ADDRESS:
            result["MAPPED-ADDRESS"] = _unpack_address(val)
        elif attr_type == ATTR_XOR_MAPPED_ADDRESS:
            try:
                result["XOR-MAPPED-ADDRESS"] = _unpack_xor_address(val)
            except Exception:
                pass
        elif attr_type == ATTR_REMOTE_ADDRESS:
            result["REMOTE-ADDRESS"] = _unpack_address(val)
        elif attr_type == ATTR_DESTINATION_ADDRESS:
            result["DESTINATION-ADDRESS"] = _unpack_address(val)
        elif attr_type == ATTR_USERNAME:
            result["USERNAME"] = val.decode("utf-8", errors="replace")
        elif attr_type == ATTR_MESSAGE_INTEGRITY:
            result["MESSAGE-INTEGRITY"] = val
        elif attr_type == ATTR_REALM:
            result["REALM"] = val.decode("utf-8", errors="replace")
        elif attr_type == ATTR_NONCE:
            result["NONCE"] = val
        elif attr_type == ATTR_LIFETIME:
            result["LIFETIME"] = unpack("!I", val)[0]
        elif attr_type == ATTR_ERROR_CODE:
            result["ERROR-CODE"] = _unpack_error_code(val)
        elif attr_type == ATTR_DATA:
            result["DATA"] = val
        elif attr_type == ATTR_MAGIC_COOKIE:
            result["MAGIC-COOKIE"] = unpack("!I", val)[0]
        elif attr_type == ATTR_MS_VERSION:
            result["MS-VERSION"] = unpack("!H", val[:2])[0] if len(val) >= 2 else 0
        elif attr_type == ATTR_MS_SEQUENCE_NUMBER:
            result["MS-SEQUENCE-NUMBER"] = val
    return result


class MTurnTransactionError(Exception):
    pass


class MTurnTransactionFailed(MTurnTransactionError):
    def __init__(self, message: MTurnMessage, attrs: dict) -> None:
        self.message = message
        self.attrs = attrs

    def __str__(self) -> str:
        err = self.attrs.get("ERROR-CODE")
        if err:
            return f"MS-TURN error {err[0]}: {err[1]}"
        return "MS-TURN transaction failed"


class MTurnTransactionTimeout(MTurnTransactionError):
    def __str__(self) -> str:
        return "MS-TURN transaction timed out"


class MTurnClient(asyncio.DatagramProtocol):
    """
    UDP-based MS-TURN client.

    Handles the MS-TURN allocation flow:
    1. Send ALLOCATE (no auth) → 401 with REALM+NONCE
    2. Send ALLOCATE (with auth) → MAPPED-ADDRESS (relay address)

    After allocation, relays data using Send/Receive (Send Request / Data Indication).
    """

    def __init__(
        self,
        server: tuple[str, int],
        username: str,
        password: str,
        lifetime: int = DEFAULT_ALLOCATION_LIFETIME,
    ) -> None:
        self.server = server
        self.username = username
        self.password = password
        self.lifetime = lifetime

        self.transport: Optional[asyncio.DatagramTransport] = None
        self.relayed_address: Optional[tuple[str, int]] = None
        self.receiver: Optional[asyncio.DatagramProtocol] = None

        self._integrity_key: Optional[bytes] = None
        self._realm: Optional[str] = None
        self._nonce: Optional[bytes] = None

        # Map transaction_id → (future, retries_left, timeout_handle, request)
        self._pending: dict[bytes, tuple[asyncio.Future, int, Optional[asyncio.TimerHandle], MTurnMessage]] = {}

        self._refresh_task: Optional[asyncio.Task] = None

    # ── asyncio.DatagramProtocol ────────────────────────────────────────────

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self.transport = transport

    def connection_lost(self, exc: Optional[Exception]) -> None:
        logger.debug("MTurnClient connection_lost: %s", exc)
        if self.receiver:
            self.receiver.connection_lost(exc)
        for txn_id, (fut, _, handle, _) in list(self._pending.items()):
            if handle:
                handle.cancel()
            if not fut.done():
                fut.set_exception(MTurnTransactionError("Connection lost"))

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if addr != self.server:
            return
        try:
            msg = parse_mturn_message(data)
        except ValueError as e:
            logger.debug("MTurnClient: failed to parse message: %s", e)
            return

        logger.debug("MTurnClient < %s", msg)
        attrs = _parse_attrs(msg)

        # Raw relay mode: data arrives without STUN wrapper
        # (only active after Set-Active-Destination — not parsed here)

        if msg.is_indication and msg.method == MTURN_METHOD_SEND:
            # Data Indication: relay to ICE layer
            peer_addr = attrs.get("REMOTE-ADDRESS")
            payload = attrs.get("DATA")
            if peer_addr and payload and self.receiver:
                self.receiver.datagram_received(payload, peer_addr)
            return

        txn_id = msg.transaction_id
        if txn_id in self._pending:
            fut, _, handle, _ = self._pending.pop(txn_id)
            if handle:
                handle.cancel()
            if not fut.done():
                if msg.is_error:
                    fut.set_exception(MTurnTransactionFailed(msg, attrs))
                else:
                    fut.set_result((msg, attrs))

    def error_received(self, exc: Exception) -> None:
        logger.warning("MTurnClient error_received: %s", exc)

    # ── Public API ──────────────────────────────────────────────────────────

    async def connect(self) -> tuple[str, int]:
        """
        Perform ALLOCATE and return the relayed (relay) address.
        """
        # Step 1: unauthenticated ALLOCATE to get REALM+NONCE
        request = self._make_allocate_request(authenticated=False)
        try:
            _, _ = await self._send_request(request)
            # Unexpected success without auth — server is lenient
        except MTurnTransactionFailed as e:
            err_code = e.attrs.get("ERROR-CODE", (0, ""))[0]
            if err_code == 401:
                self._realm = e.attrs.get("REALM")
                self._nonce = e.attrs.get("NONCE")
                if not self._realm or not self._nonce:
                    raise MTurnTransactionError(
                        "401 response missing REALM or NONCE"
                    ) from e
                self._integrity_key = _make_integrity_key(
                    self.username, self._realm, self.password
                )
                logger.debug(
                    "MTurnClient: got 401, realm=%r, retrying with auth", self._realm
                )
            else:
                raise

        if self._integrity_key:
            # Step 2: authenticated ALLOCATE
            request2 = self._make_allocate_request(authenticated=True)
            response, attrs = await self._send_request(request2)
        else:
            raise MTurnTransactionError("Allocation succeeded without credentials (unexpected)")

        # Extract relay address — prefer MAPPED-ADDRESS per MS-TURN spec
        relay = attrs.get("MAPPED-ADDRESS") or attrs.get("XOR-MAPPED-ADDRESS")
        if not relay:
            raise MTurnTransactionError(
                "ALLOCATE response missing relay address"
            )
        self.relayed_address = relay
        ttl = attrs.get("LIFETIME", self.lifetime)
        logger.info("MTurnClient: allocated relay address %s (lifetime %ds)", relay, ttl)

        self._refresh_task = asyncio.create_task(self._refresh_loop(ttl))
        return relay

    async def send_data(self, data: bytes, peer_addr: tuple[str, int]) -> None:
        """
        Send data to peer_addr via MS-TURN Send Request.
        """
        msg = MTurnMessage(MTURN_SEND_REQUEST)
        msg.add_magic_cookie()
        msg.add_attr(ATTR_DESTINATION_ADDRESS, _pack_address(*peer_addr))
        msg.add_attr(ATTR_DATA, data)
        if self._integrity_key:
            self._add_auth_attrs(msg)
            msg.add_message_integrity(self._integrity_key)
        self._send_raw(bytes(msg))

    async def delete(self) -> None:
        """Cancel the allocation."""
        if self._refresh_task:
            self._refresh_task.cancel()
            self._refresh_task = None
        if self.transport:
            self.transport.close()

    # ── Internals ───────────────────────────────────────────────────────────

    def _make_allocate_request(self, authenticated: bool) -> MTurnMessage:
        msg = MTurnMessage(MTURN_ALLOCATE_REQUEST)
        msg.add_magic_cookie()
        msg.add_attr(ATTR_BANDWIDTH, pack("!I", 750))  # 750 kbps (Teams default)
        msg.add_attr(ATTR_LIFETIME, pack("!I", self.lifetime))
        if authenticated and self._integrity_key:
            self._add_auth_attrs(msg)
            msg.add_message_integrity(self._integrity_key)
        return msg

    def _add_auth_attrs(self, msg: MTurnMessage) -> None:
        """Append USERNAME, REALM, NONCE to the message (before MESSAGE-INTEGRITY)."""
        msg.add_attr(ATTR_USERNAME, self.username.encode("utf-8"))
        if self._realm:
            msg.add_attr(ATTR_REALM, self._realm.encode("utf-8"))
        if self._nonce:
            msg.add_attr(ATTR_NONCE, self._nonce)

    def _send_raw(self, data: bytes) -> None:
        if self.transport:
            self.transport.sendto(data)

    async def _send_request(
        self,
        msg: MTurnMessage,
        retries: int = RETRY_MAX,
    ) -> tuple[MTurnMessage, dict]:
        """Send a message and await the response (with retransmission)."""
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[tuple[MTurnMessage, dict]] = loop.create_future()
        delay = RETRY_RTO

        def retry(remaining: int, current_delay: float) -> None:
            if fut.done():
                return
            self._send_raw(bytes(msg))
            if remaining > 0:
                handle = loop.call_later(
                    current_delay, retry, remaining - 1, current_delay * 2
                )
            else:
                handle = loop.call_later(
                    current_delay,
                    lambda: fut.set_exception(MTurnTransactionTimeout())
                    if not fut.done() else None,
                )
            self._pending[msg.transaction_id] = (fut, remaining, handle, msg)

        retry(retries, delay)
        return await fut

    async def _refresh_loop(self, ttl: int) -> None:
        """Periodically refresh the allocation before it expires."""
        while True:
            await asyncio.sleep(ttl * 5 // 6)
            try:
                msg = self._make_allocate_request(authenticated=True)
                _, attrs = await self._send_request(msg)
                ttl = attrs.get("LIFETIME", self.lifetime)
                logger.info("MTurnClient: allocation refreshed (lifetime %ds)", ttl)
            except MTurnTransactionError as e:
                logger.warning("MTurnClient: refresh failed: %s", e)


class MTurnTransport:
    """
    Wraps MTurnClient to look like an asyncio DatagramTransport.
    Used by aioice's ICE layer as the underlying transport for a relay candidate.
    """

    def __init__(self, client: MTurnClient) -> None:
        self._client = client
        self._relayed_address: Optional[tuple[str, int]] = None

    def close(self) -> None:
        asyncio.create_task(self._client.delete())

    def get_extra_info(self, name: str, default=None):
        if name == "sockname":
            return self._relayed_address
        if name == "related_address":
            return self._client.transport.get_extra_info("sockname") if self._client.transport else default
        return default

    def sendto(self, data: bytes, addr: tuple[str, int]) -> None:
        asyncio.create_task(self._client.send_data(data, addr))

    async def _connect(self, protocol: asyncio.DatagramProtocol) -> None:
        self._relayed_address = await self._client.connect()
        self._client.receiver = protocol
        protocol.connection_made(self)  # type: ignore[arg-type]


async def create_mturn_endpoint(
    protocol_factory,
    server_addr: tuple[str, int],
    username: str,
    password: str,
    lifetime: int = DEFAULT_ALLOCATION_LIFETIME,
):
    """
    Create a datagram endpoint relayed over MS-TURN.

    Returns (MTurnTransport, protocol) analogous to create_turn_endpoint.
    """
    loop = asyncio.get_running_loop()

    client = MTurnClient(
        server=server_addr,
        username=username,
        password=password,
        lifetime=lifetime,
    )

    # Resolve hostname → IP if needed
    host = server_addr[0]
    host = await loop.run_in_executor(None, socket.gethostbyname, host)
    resolved_addr = (host, server_addr[1])
    client.server = resolved_addr

    inner_transport, _ = await loop.create_datagram_endpoint(
        lambda: client,
        remote_addr=resolved_addr,
    )

    try:
        protocol = protocol_factory()
        turn_transport = MTurnTransport(client)
        await turn_transport._connect(protocol)
    except Exception:
        inner_transport.close()
        raise

    return turn_transport, protocol
