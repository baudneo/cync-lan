from typing import Iterable, List

from .builder import PacketBuilder

__all__ = ["PacketFramer", "HEADER_LEN", "MAX_PACKET_LEN"]

HEADER_LEN = 5
# Length is byte3*256 + byte4 (+5 header), so 65540 is the protocol maximum. Real
# traffic is far smaller; anything above this cap is treated as a corrupt header.
MAX_PACKET_LEN = 8192


class PacketFramer:
    """
    Turns a TCP byte stream into complete Cync packets.

    Pure and synchronous: feed() bytes in, get a list of complete packets out. Any
    incomplete trailing packet is kept in an internal buffer until more data arrives.
    Bytes that cannot start a packet are skipped (resync) and counted in
    ``dropped_bytes``.
    """

    def __init__(
        self,
        valid_headers: Iterable[int] = PacketBuilder.ALL_HEADERS,
        max_packet_len: int = MAX_PACKET_LEN,
    ):
        self._valid = frozenset(valid_headers)
        self._max = max_packet_len
        self._buf = bytearray()
        self.dropped_bytes = 0
        self.resyncs = 0

    @property
    def pending(self) -> int:
        """Number of buffered bytes waiting for the rest of a packet."""
        return len(self._buf)

    def reset(self) -> None:
        self._buf.clear()

    def feed(self, data: bytes) -> List[bytes]:
        if data:
            self._buf.extend(data)
        packets: List[bytes] = []
        buf = self._buf
        while buf:
            if buf[0] not in self._valid:
                self._skip_garbage()
                continue
            if len(buf) < HEADER_LEN:
                break  # partial header, wait for more
            total = buf[3] * 256 + buf[4] + HEADER_LEN
            if total > self._max:
                # corrupt length: drop this header byte and look for the next one
                self._drop(1)
                continue
            if len(buf) < total:
                break  # partial payload, wait for more
            packets.append(bytes(buf[:total]))
            del buf[:total]
        return packets

    def _skip_garbage(self) -> None:
        buf = self._buf
        n = 1
        while n < len(buf) and buf[n] not in self._valid:
            n += 1
        self._drop(n)

    def _drop(self, n: int) -> None:
        del self._buf[:n]
        self.dropped_bytes += n
        self.resyncs += 1
