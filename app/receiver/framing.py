"""Turning bytes off the wire into individual syslog messages. No parsing happens here."""

import re

# Octet-counted frames larger than this close the connection (nobody sends 1 MiB syslog lines;
# accepting it would let one client pin memory).
OCTET_HARD_MAX = 1024 * 1024
_OCTET_RE = re.compile(rb"(\d{1,7}) ")
_DIGITS_RE = re.compile(rb"\d{1,7}")


class FramingError(Exception):
    pass


def clean(data: bytes, max_bytes: int) -> tuple[str, bool]:
    """bytes -> (text, truncated). Strips trailing CR/LF/NUL, decodes UTF-8 leniently, removes NUL
    (PostgreSQL text cannot hold it). Never raises."""
    truncated = len(data) > max_bytes
    if truncated:
        data = data[:max_bytes]
    data = data.rstrip(b"\r\n\x00")
    text = data.decode("utf-8", errors="replace").replace("\x00", "�")
    return text, truncated


class TcpFramer:
    """RFC 6587 framing, detected per frame:
    - octet counting: ``<len> SP <msg>``
    - non-transparent: messages terminated by LF (CRLF and NUL tolerated)
    Oversized LF-framed messages are truncated to ``max_bytes``; the rest up to the next LF is discarded."""

    def __init__(self, max_bytes: int):
        self.max = max_bytes
        self.buf = bytearray()
        self.discarding = False

    def feed(self, data: bytes) -> list[tuple[bytes, bool]]:
        self.buf += data
        out: list[tuple[bytes, bool]] = []
        while self.buf:
            if self.discarding:
                i = self.buf.find(b"\n")
                if i < 0:
                    self.buf.clear()
                    break
                del self.buf[: i + 1]
                self.discarding = False
                continue

            if self.buf[:1].isdigit():
                m = _OCTET_RE.match(self.buf)
                if m is None and _DIGITS_RE.fullmatch(self.buf):
                    break  # length prefix still arriving
                if m is not None:
                    n = int(m.group(1))
                    if n > OCTET_HARD_MAX:
                        raise FramingError(f"octet-counted frame of {n} bytes exceeds hard limit")
                    start = m.end()
                    if len(self.buf) < start + n:
                        break  # wait for the rest of the frame
                    frame = bytes(self.buf[start : start + n])
                    del self.buf[: start + n]
                    if frame.strip(b"\r\n\x00 "):
                        out.append((frame[: self.max], n > self.max))
                    continue

            i = self.buf.find(b"\n")
            if i < 0:
                if len(self.buf) > self.max:
                    out.append((bytes(self.buf[: self.max]), True))
                    self.buf.clear()
                    self.discarding = True
                break
            frame = bytes(self.buf[:i])
            del self.buf[: i + 1]
            if frame.strip(b"\r\x00 "):
                out.append((frame[: self.max], len(frame) > self.max))
        return out

    def remainder(self) -> bytes | None:
        """Unterminated data left when the peer closes (sent without a trailing LF)."""
        if self.discarding or not self.buf.strip(b"\r\n\x00 "):
            return None
        return bytes(self.buf[: self.max])
