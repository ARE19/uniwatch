"""Async UDP + TCP syslog listeners. Run with:  python -m app.receiver"""

import asyncio
import logging
import signal
import socket
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from app.config import Settings, get_settings
from app.receiver.framing import FramingError, TcpFramer
from app.receiver.ipfix import IpfixDecoder
from app.receiver.pipeline import Pipeline

log = logging.getLogger("receiver")


class _Udp(asyncio.DatagramProtocol):
    def __init__(self, pipeline: Pipeline):
        self.p = pipeline

    def datagram_received(self, data: bytes, addr) -> None:
        self.p.submit(addr[0], "udp", data)

    def error_received(self, exc: Exception) -> None:
        self.p.stats["udp_errors"] += 1


class NetflowCapture(asyncio.DatagramProtocol):
    """NetFlow/IPFIX on UDP: each flow record becomes one raw line (JSON, transport 'netflow') of the sending device,
    unless that device's flows already come from the controller API. The first datagrams from each sender are also
    kept as hex lines (<dir>/<ip>.hex) as real samples for new exporters."""

    def __init__(self, directory: str, max_per_source: int, pipeline: "Pipeline | None" = None):
        self.dir = Path(directory)
        self.max = max_per_source
        self.counts: Counter[str] = Counter()
        self.pipeline = pipeline
        self.decoder = IpfixDecoder()

    def datagram_received(self, data: bytes, addr) -> None:
        src = addr[0]
        self.counts[src] += 1
        if self.counts[src] == 1:
            log.info("netflow: first datagram from %s (%d bytes)", src, len(data))
        if self.pipeline is not None:
            self._ingest(src, data)
        if self.counts[src] > self.max:
            return
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            with open(self.dir / f"{src}.hex", "a", encoding="ascii") as f:
                f.write(f"{datetime.now(UTC).isoformat()} {data.hex()}\n")
        except OSError as e:
            log.warning("netflow capture write failed: %s", e)

    def _ingest(self, src: str, data: bytes) -> None:
        try:
            flows = self.decoder.decode(src, data)    # also learns templates, even from devices we skip
        except Exception:  # noqa: BLE001 - a malformed datagram must not stop the receiver
            log.exception("netflow decode failed for %s", src)
            return
        dev = self.pipeline.devices.get(src)
        if dev is not None and dev.api_flows:
            self.pipeline.stats["netflow_skipped_api"] += len(flows)
            return
        for f in flows:
            self.pipeline.submit(src, "netflow", json.dumps(f, separators=(",", ":")).encode())


class Receiver:
    def __init__(self, settings: Settings):
        self.s = settings
        self.pipeline = Pipeline(settings)
        self.udp_transports: list[asyncio.DatagramTransport] = []
        self.tcp_servers: list[asyncio.base_events.Server] = []
        self.tcp_active = 0
        self._pipeline_task: asyncio.Task | None = None
        self.udp_port = 0
        self.tcp_port = 0

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        # Load device mappings before listening so the first packets are attributed correctly.
        try:
            await self.pipeline.refresh_devices()
        except Exception as e:  # noqa: BLE001 — still listen; lines are kept in memory until the DB returns
            log.error("initial device load failed: %s", e)
        self._pipeline_task = asyncio.create_task(self.pipeline.run(), name="pipeline")

        udp_ports = [self.s.receiver_udp_port, *self.s.receiver_extra_port_list()]
        tcp_ports = [self.s.receiver_tcp_port, *self.s.receiver_extra_port_list()]
        for port in dict.fromkeys(udp_ports):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.s.receiver_udp_rcvbuf)
            sock.bind((self.s.receiver_bind, port))
            transport, _ = await loop.create_datagram_endpoint(lambda: _Udp(self.pipeline), sock=sock)
            self.udp_transports.append(transport)
            rcvbuf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        self.netflow: NetflowCapture | None = None
        if self.s.receiver_netflow_port:
            self.netflow = NetflowCapture(self.s.netflow_capture_dir, self.s.netflow_capture_max, self.pipeline)
            t, _ = await loop.create_datagram_endpoint(lambda: self.netflow,
                                                       local_addr=(self.s.receiver_bind, self.s.receiver_netflow_port))
            self.udp_transports.append(t)
        for port in dict.fromkeys(tcp_ports):
            server = await asyncio.start_server(self._tcp_client, self.s.receiver_bind, port, reuse_address=True)
            self.tcp_servers.append(server)
        # First listener of each kind is the "main" one (tests bind port 0 and read it back).
        self.udp_port = self.udp_transports[0].get_extra_info("sockname")[1]
        self.tcp_port = self.tcp_servers[0].sockets[0].getsockname()[1]
        log.info("listening udp %s tcp %s on %s (SO_RCVBUF=%d)",
                 [t.get_extra_info("sockname")[1] for t in self.udp_transports],
                 [s.sockets[0].getsockname()[1] for s in self.tcp_servers], self.s.receiver_bind, rcvbuf)

    async def _tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ip = writer.get_extra_info("peername")[0]
        if self.tcp_active >= self.s.receiver_tcp_max_connections:
            self.pipeline.stats["tcp_rejected"] += 1
            writer.close()
            return
        self.tcp_active += 1
        framer = TcpFramer(self.s.receiver_max_message_bytes)
        try:
            while True:
                data = await asyncio.wait_for(reader.read(65536), self.s.receiver_tcp_idle_seconds)
                if not data:
                    break
                for frame, truncated in framer.feed(data):
                    self.pipeline.submit(ip, "tcp", frame, truncated)
            if (rest := framer.remainder()) is not None:
                self.pipeline.submit(ip, "tcp", rest)
        except FramingError as e:
            self.pipeline.stats["tcp_framing_errors"] += 1
            log.warning("closing tcp from %s: %s", ip, e)
        except (TimeoutError, ConnectionError):
            pass
        finally:
            self.tcp_active -= 1
            writer.close()

    async def stop(self) -> None:
        for t in self.udp_transports:
            t.close()
        for srv in self.tcp_servers:
            srv.close()
        self.pipeline.request_stop()
        if self._pipeline_task is not None:
            await self._pipeline_task
        await self.pipeline.drain()


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    r = Receiver(get_settings())
    await r.start()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    log.info("shutting down: draining %d queued messages", len(r.pipeline.queue))
    await r.stop()
