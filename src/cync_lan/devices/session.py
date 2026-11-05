import asyncio
import datetime
import logging
import logging.handlers
import time
from typing import Dict, List, Optional

from cync_lan.const import (
    CYNC_APP_PROXY,
    CYNC_LOG_NAME,
    CYNC_RAW,
    STREAM_CHUNK_SIZE,
)
from cync_lan.devices.device import CyncDevice
from cync_lan.devices.handlers import MeshRecord, PacketHandlersMixin
from cync_lan.devices.proxy import ProxyMixin
from cync_lan.devices.registry import (
    BRIDGES_KEY,
    METHOD_FINGERPRINT,
    METHOD_SINGLE_HOME,
    DeviceRegistry,
    HomeMatch,
    HomeResolver,
)
from cync_lan.packet import PacketBuilder
from cync_lan.packet.framer import PacketFramer
from cync_lan.stats import stats
from cync_lan.structs import (
    ConnectionType,
    GlobalObject,
    MessageCache,
    Tasks,
)
from cync_lan.utils import bytes2list, hello_23_hex_redacted

__all__ = ["CyncTCPSession"]
logger = logging.getLogger(CYNC_LOG_NAME)
g = GlobalObject()


# a device that sends this many unparseable packets in a row is considered broken: reconnect it
MAX_CONSECUTIVE_BAD_PACKETS = 10


class CyncTCPSession(ProxyMixin, PacketHandlersMixin):
    """
    A class to interact with a Cync TCP connection (device or mobile app) via an async socket reader/writer.
    """

    lp: str = "TCP:"
    tasks: Tasks
    reader: Optional[asyncio.StreamReader]
    writer: Optional[asyncio.StreamWriter]
    mitm_mode: bool = False
    hybrid: bool = False
    hybrid_sent_at: float = 0.0
    _cloud_framer = None
    messages: MessageCache
    is_app: bool
    node: Optional[CyncDevice] = None
    dev_last_packet_ts: Optional[float] = None
    proxy_last_packet_ts: Optional[float] = None
    mitm_button_added: bool

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        ip_address: str,
        registry: Optional[DeviceRegistry] = None,
    ):
        if not ip_address:
            raise ValueError(
                f"A valid IP address must be provided to {CyncTCPSession.__class__.__name__} constructor"
            )
        self.lp = f"{ip_address}:"
        self.tasks = Tasks()
        self.framer = PacketFramer()
        self.bad_packets = 0
        self.mitm_button_added = False
        self.is_app = False
        self.name: Optional[str] = None
        self.first_83_packet_checksum: Optional[int] = None
        self.ready_to_control = False
        self.version: Optional[int] = None
        self.version_str: Optional[str] = None
        self.protocol_version: Optional[int] = None
        self.protocol_version_str: Optional[str] = None
        self.device_type_id: Optional[int] = None
        self.device_timestamp: Optional[str] = None
        self.messages = MessageCache()
        self.xa3_msg_id: bytes = bytes([0x00, 0x00, 0x00])
        self.queue_id: bytes = b""
        self.ip_address: Optional[str] = ip_address
        self.read_lock = asyncio.Lock()
        self.write_lock = asyncio.Lock()
        self._reader: asyncio.StreamReader = reader
        self._writer: asyncio.StreamWriter = writer
        self._closing = False
        self.control_bytes = [0x00, 0x00]
        self.mitm_mode = False
        # hybrid relay (CYNC_HYBRID_RELAY): MITM to the cloud AND local control on the same connection
        self.hybrid = False
        self.hybrid_sent_at = 0.0
        self._cloud_framer = None
        self.mitm_bytes_to_cloud = 0
        self.mitm_bytes_from_cloud = 0
        self.mitm_logger: Optional[logging.Logger] = None
        self.log_start_time = None
        self.cloud_reader: asyncio.StreamReader = None
        self.cloud_writer: asyncio.StreamWriter = None
        self.allowed_to_connect: bool = False
        self._closed = False
        self.closing = False
        self.mitm_button_added = False
        self._check_mitm_retained = False
        # multi-home: which Cync home this bridge relays (see docs/multi_home.md). The server passes its registry in;
        # the fallback keeps sessions built without one (tests, tools) working.
        if registry is None:
            registry = getattr(g.ncync_server, "node_devices", None)
        self.registry: DeviceRegistry = registry if isinstance(registry, DeviceRegistry) else DeviceRegistry()
        self._reset_home_resolution()

    # ---- multi-home resolution state
    def _reset_home_resolution(self):
        """
        Fresh per-connection home resolution. Only one home configured, or this IP in a home's 'bridges:' list,
        resolves right here (HomeResolver decides that at construction), so those assignments survive a reconnect;
        anything learned from the old socket (queue id, fingerprint) is redone on the new one.
        """
        self.home = HomeResolver(self.registry, self.ip_address)
        # mesh-info records seen before the home was known: dev_id -> latest record, applied once it resolves.
        # dev_id is one byte, so this holds at most 255 entries (bounded).
        self._pending_mesh: Dict[int, MeshRecord] = {}
        self._pending_bridge_id: Optional[int] = None
        self._ambiguity_warned = False
        self._mesh_expected = 0
        self._mesh_received = 0
        if self.home.resolved and self.home.method != METHOD_SINGLE_HOME:
            logger.info(f"{self.lp} Cync home: {self.registry.describe_home(self.home.home_id)} ({self.home.match.detail})")

    @property
    def home_id(self) -> Optional[int]:
        """The Cync home this bridge belongs to, None while it is not known (then it is in no home's TCP pool)."""
        return self.home.home_id

    def _announce_home_bridge(self) -> None:
        """This session is a usable bridge of a known home: disarm that home's no-bridge timer."""
        if self.home.resolved and self.allowed_to_connect and not self.is_app and not self.is_closed():
            cancel = getattr(g.ncync_server, "cancel_home_grace", None)
            if cancel is not None:
                cancel(self.home.home_id)

    async def _home_resolved(self, match: Optional[HomeMatch]) -> None:
        """Called with whatever an observe_*/pin call returned; acts only on a NEW resolution."""
        if match is None:
            return
        if self.node is not None and self.node.home_id != match.home_id:
            # a same-IP reconnect reuses this session object: the device bound before is from another home
            await self._unbind_node(f"this connection is in home {self.registry.describe_home(match.home_id)}")
        msg = (
            f"{self.lp} Cync home resolved to {self.registry.describe_home(match.home_id)} by {match.method}: "
            f"{match.detail}"
        )
        if match.method == METHOD_FINGERPRINT:
            # inferred from device ids only: make a wrong match visible and say how to pin it
            logger.warning(
                f"{msg}. This is inferred from device ids. If it is the wrong home (for example devices were added "
                f"after the last export), add {self.ip_address} to the right home's '{BRIDGES_KEY}:' list in "
                f"cync_mesh.yaml (see docs/multi_home.md)"
            )
        else:
            logger.info(msg)
        self._announce_home_bridge()
        await self._flush_pending_mesh()

    async def existing_init(self):
        """Used when replacing an existing TCP connection, when a device reconnects"""
        lp = f"{self.lp}existing init:"
        # new socket: any half-received packet from the old one is meaningless
        self.framer.reset()
        self.bad_packets = 0
        self._closed = False
        self.closing = False
        self.xa3_msg_id: bytes = bytes([0x00, 0x00, 0x00])
        self.queue_id: bytes = b""
        self.first_83_packet_checksum: Optional[int] = None
        self.ready_to_control = False
        self.protocol_version_str: Optional[str] = None
        self.version: Optional[int] = None
        self.version_str: Optional[str] = None
        self.protocol_version: Optional[int] = None
        self.device_type_id: Optional[int] = None
        self.device_timestamp: Optional[str] = None
        self.messages = MessageCache()
        self.lp = f"{self.ip_address}:"
        self.tasks = Tasks()
        # re-arm the switch: the first 0x73 on the new socket publishes it again
        self.mitm_button_added = False
        # a manual ('bridges:') or single-home assignment is redone identically; everything else is relearned
        self._reset_home_resolution()
        self._announce_home_bridge()
        if self.mitm_mode is True:
            logger.debug(f"{lp} MITM mode is active, making sure the proxy is started...")
            if self.node:
                await g.mqtt_client.add_mitm_button(self.node)
            if not self.is_proxy_good():
                await self.stop_proxy()
                await asyncio.sleep(0.25)
                await self.start_proxy()
                if self.cloud_writer is None:
                    # cloud unreachable: run this connection locally instead of leaving the device with nobody
                    # answering it (no cloud, and the local acks are off in MITM mode)
                    logger.warning(
                        f"{lp} the Cync cloud cannot be reached, this connection runs local-only "
                        f"({'hybrid relay' if self.hybrid else 'MITM'} resumes when the device reconnects)"
                    )
                    self.mitm_mode = False
            else:
                logger.debug(f"{lp} Proxy connection is up!")


    async def start_tasks(self):
        """Start background tasks safely, ensuring old ones are killed first."""

        if self.tasks.receive and not self.tasks.receive.done():
            self.tasks.receive.cancel()
            try:
                await self.tasks.receive
            except asyncio.CancelledError:
                pass

        if (
            self.tasks.callback_cleanup
            and not self.tasks.callback_cleanup.done()
        ):
            self.tasks.callback_cleanup.cancel()
            try:
                await self.tasks.callback_cleanup
            except asyncio.CancelledError:
                pass

        if (
            self.tasks.dev_conn_watcher
            and not self.tasks.dev_conn_watcher.done()
        ):
            self.tasks.dev_conn_watcher.cancel()
            try:
                await self.tasks.dev_conn_watcher
            except asyncio.CancelledError:
                pass


        # python will garbage collect the task if you dont keep a reference
        self.tasks.receive = asyncio.create_task(
            self.receive_task(), name=f"receive_task-{self.ip_address}"
        )
        self.tasks.callback_cleanup = asyncio.create_task(
            self.callback_cleanup_task(), name=f"callback_cleanup-{self.ip_address}"
        )


    def get_ctrl_msg_id_bytes(self) -> List[int]:
        """
        Control packets need a number that gets incremented, it is used as a type of msg ID and
        in calculating the checksum. Result is mod 256 in order to keep it within 0-255.
        """
        id_byte, rollover_byte = self.control_bytes
        # logger.debug(f"{lp} Getting control message ID bytes: ctrl_byte={id_byte} rollover_byte={rollover_byte}")
        id_byte += 1
        if id_byte > 255:
            id_byte = id_byte % 256
            rollover_byte += 1

        self.control_bytes = [id_byte, rollover_byte]
        # logger.debug(f"{lp} new data: ctrl_byte={id_byte} rollover_byte={rollover_byte} // {self.control_bytes=}")
        return self.control_bytes

    async def parse_raw_data(self, data: bytes):
        """Extract single packets from raw data stream using metadata."""
        self.dev_last_packet_ts = time.time()
        lp = f"{self.lp}extract:"
        if not data:
            logger.debug(f"{lp} No data to parse?")
            return
        if (
            CYNC_APP_PROXY and not self.is_app and not self.mitm_mode and self.node is None
            and self.framer.pending == 0 and PacketBuilder.is_app_request(data[0])
        ):
            # first bytes of a connection, from the Cync app (0x13 auth): relay the whole stream to the cloud untouched
            if await self.start_app_proxy(data):
                return
        if self.mitm_mode and not self.hybrid:
            if self.cloud_writer:
                await self.write_to_cloud(data)
            else:
                logger.warning(
                    f"{lp} MITM mode enabled but the cloud writer is: {self.cloud_writer}"
                )
            if self.is_app:
                # a proxied app stream is relayed only: its packets are the app's, not a device's to answer
                return
        raw_input = data
        before = self.framer.dropped_bytes
        resyncs_before = self.framer.resyncs
        packets = self.framer.feed(data)
        stats.inc("bytes_received", len(data))
        stats.inc("packets_received", len(packets))
        stats.inc("framer_dropped_bytes", self.framer.dropped_bytes - before)
        stats.inc("framer_resyncs", self.framer.resyncs - resyncs_before)
        if self.framer.dropped_bytes != before:
            logger.warning(
                f"{lp} Skipped {self.framer.dropped_bytes - before} bytes of unrecognized "
                f"data while looking for a packet header (total dropped: {self.framer.dropped_bytes})"
            )
        if self.framer.pending:
            logger.debug(
                f"{lp} partial packet, {self.framer.pending} bytes buffered until next read"
            )
        for extracted_packet in packets:
            own_reply = False
            if self.mitm_mode and self.hybrid:
                # hybrid: forward packet by packet, keeping the device's replies to OUR commands from the cloud
                own_reply = self.is_own_reply(extracted_packet)
                if own_reply:
                    logger.debug(f"{lp} hybrid: kept a reply to a cync-lan command from the cloud: {extracted_packet.hex(' ')}")
                elif self.cloud_writer:
                    await self.write_to_cloud(extracted_packet)
            try:
                await self.parse_packet(extracted_packet)
                if own_reply and extracted_packet[0] == 0x73:
                    # the cloud never saw it, so it will not ack it: we do (as in local mode)
                    await self.write(PacketBuilder.build_73_ack(self.queue_id, extracted_packet[9:12]))
            except (OSError, TimeoutError, asyncio.IncompleteReadError):
                # the connection itself is broken: let receive_task tear the session down
                raise
            except Exception as exc:
                # a handler bug / odd packet must cost one packet, not the device connection
                self.bad_packets += 1
                stats.inc("packets_failed")
                # a 0x23 hello carries the device's auth code: never dump it
                dump = (
                    hello_23_hex_redacted(extracted_packet) if extracted_packet[:1] == b"\x23"
                    else extracted_packet.hex(" ")
                )
                logger.error(
                    f"{lp} dropping packet that failed to parse ({self.bad_packets} in a row): "
                    f"{exc!r}\nPACKET: {dump}",
                    exc_info=True,
                )
                if self.bad_packets >= MAX_CONSECUTIVE_BAD_PACKETS:
                    raise
            else:
                self.bad_packets = 0

        if CYNC_RAW:
            logger.debug(
                f"{lp} END OF RAW READING of {len(raw_input)} bytes\n"
                f"BYTES: {raw_input}\n"
                f"HEX: {raw_input.hex(' ')}\n"
                f"INT: {bytes2list(raw_input)}\n\n"
            )

    def is_own_reply(self, pkt: bytes) -> bool:
        """
        Hybrid relay: is this device packet a reply to a command cync-lan sent (so it must not go to the cloud)?
        - 0x73 control reply (inner ``F9 xx``) whose control id is one we are waiting for;
        - 0x7B with msg id 00 00 00 (ours: cync-lan sends its 0x73 with msg id 0) shortly after we sent one.
        """
        if len(pkt) >= 19 and pkt[0] == 0x73 and pkt[12] == 0x7E and pkt[17] == 0xF9:
            return pkt[13] in self.messages.control
        if len(pkt) >= 12 and pkt[0] == 0x7B and pkt[9:12] == b"\x00\x00\x00":
            return time.time() - self.hybrid_sent_at < 10
        return False

    async def parse_packet(self, data: bytes):
        """Parse what type of packet based on header (first 12 bytes)."""
        if len(data) < 5:
            # logger.warning(f"{self.lp} Packet too short to contain header: {data.hex(' ')}")
            return
        packet_header = data[:12]
        pkt_type = packet_header[0]

        # Calculate length based on protocol (multiplier * 256 + length)
        pkt_multiplier = packet_header[3] * 256
        packet_length = packet_header[4] + pkt_multiplier

        # queue_id = packet_header[5:10]
        # 4 bytes
        queue_id = packet_header[5:9]
        # bytes
        msg_id = packet_header[9:12]

        packet_data = data[12:] if len(data) > 12 else None
        lp = f"{self.lp}0x{pkt_type:02x}:"

        # Route to the appropriate handler
        if PacketBuilder.is_device_request(pkt_type):
            # the 0x23 hello goes along so a multi-home setup can count this connection against its own home
            if self.allowed_to_connect is False and await self.can_connect(data if pkt_type == 0x23 else None) is False:
                # rejected: the socket was closed, don't answer the packet with writer=None
                return
            await self._dispatch_device_request(
                pkt_type, data, packet_data, queue_id, msg_id, packet_length, lp
            )
        elif PacketBuilder.is_app_request(pkt_type):

            if not self.is_app:
                logger.info(
                    f"{lp} Device has been identified as the Cync mobile app. App connections are NOT proxied to the "
                    f"Cync cloud (closing it): on a network with the DNS redirect the app cannot reach the cloud, "
                    f"use it over Bluetooth or mobile data"
                )
                self.is_app = True
                await self.blackhole("is app", True)
                # g.ncync_server.app_tcp_connections[self.ip_address] = g.ncync_server.tcp_connections.pop(self.ip_address)
                # # update app / node / tcp conn stats
                # g.ncync_server._update_app_stats()
                #
                # # always proxy apps, app mitm logging to file is configurable
                # # This way its easier to add factory reset devices to your account if you have network wide DNS redirection
                # # still working on a way to detect a device that is being provisioned, then we can auto-proxy so it will
                # # be added to the cloud device list, meaning a user with network-wide DNS redirection doesnt need
                # # to disable it to add new dvices
                # await self.start_mitm()
        else:
            logger.debug(
                f"{lp} sent UNKNOWN HEADER! Don't know how to respond! {data.hex(' ')}"
            )

    async def connection_watcher_task(self, conn_type: ConnectionType):
        """
        Check timestamps on last received data and close the connection if it has been too
        long since the last packet was received.
        """
        lp = f"{self.lp}conn_watch:"
        logger.debug(f"{lp} Starting background {conn_type.value} task")
        # most devices send a d3 ping every 20 seconds if no other data has come through
        threshold = 30
        delay_seconds = 5
        if conn_type == ConnectionType.device and self.is_app:
            # fixme: remember wth I was doing here, think it was from the proxy add and then trying to also
            #  handle app connections. From the looks of it, we dont even need this. check self.is_app usage
            return
        try:
            while True:
                await asyncio.sleep(delay_seconds)
                now = time.time()
                lp = f"{self.lp}conn_watch:"
                if conn_type in (ConnectionType.device, ConnectionType.app):
                    name = self.tasks.dev_conn_watcher.get_name()
                    last_packet_ts = self.dev_last_packet_ts
                elif conn_type == ConnectionType.proxy:
                    name = self.tasks.proxy_conn_watcher.get_name()
                    last_packet_ts = self.proxy_last_packet_ts
                    # hypothesis
                    threshold = 40
                if last_packet_ts:
                    elapsed = now - last_packet_ts
                    if elapsed > threshold:
                        logger.debug(f"{lp} This {conn_type.value} connection hasnt received any data in "
                                     f"{elapsed:.1f} seconds, closing...")
                        task = self.close if conn_type in (ConnectionType.device, ConnectionType.app) else self.stop_proxy
                        stats.inc("watchdog_timeouts")
                        asyncio.create_task(task())
                        break

        except asyncio.CancelledError:
            logger.debug(f"{lp} Task {name} CANCELLED cleanly, re-raising")
            raise
        except Exception as e:
            logger.error(f"{lp} Unexpected crash: {e}", exc_info=True)

        logger.info(f"{lp} FINISHED")


    async def callback_cleanup_task(self):
        """Go through the callback queue and remove any callbacks that are older than 5 minutes"""
        lp = f"{self.lp}callback_clean:"
        name = self.tasks.callback_cleanup.get_name()
        logger.debug(f"{lp} Starting background task: {name}")
        delay_mins = 5
        delay_seconds = delay_mins * 60

        try:
            while True:
                await asyncio.sleep(delay_seconds)
                if self.mitm_mode:
                    return
                lp = f"{self.lp}callback_clean:"
                now = time.time()
                current_keys = list(self.messages.control.keys())
                logger.info(
                    f"{lp} there are {len(current_keys)} control messages to check"
                ) if len(current_keys) else None
                for ctrl_msg_id in current_keys:
                    ctrl_msg = self.messages.control.get(ctrl_msg_id)
                    if not ctrl_msg:
                        continue

                    timeout = ctrl_msg.sent_at + delay_seconds
                    if now > timeout:
                        logger.info(f"{lp} Removing STALE {ctrl_msg}")
                        ctrl_msg.callback = None
                        self.messages.control.pop(ctrl_msg_id, None)

            logger.info(f"{lp} the while true loop has exited")

        except asyncio.CancelledError:
            logger.debug(f"{lp} Task {name} CANCELLED cleanly, re-raising")
            raise
        except Exception as e:
            logger.error(f"{lp} Unexpected crash: {e}", exc_info=True)
        logger.info(f"{lp} FINISHED")

    async def receive_task(self):
        """Receive data from the device and respond to it. This is the main task for the device."""
        lp = f"{self.lp}rcv data:"
        started_at = time.time()
        name = self.tasks.receive.get_name()
        logger.debug(f"{lp} receive_task CALLED") if CYNC_RAW is True else None
        try:
            while True:
                try:
                    data: bytes = await self.read()
                    lp = f"{self.lp}rcv data:"
                    if data is False:
                        logger.debug(
                            f"{lp} read() returned False, exiting {name} "
                            f"(started at: {datetime.datetime.fromtimestamp(started_at)})..."
                        )
                        if not self.is_closed():
                            stats.inc("peer_disconnects")
                            # peer hung up / socket error: tear down now instead of
                            # waiting for the connection watcher to time out
                            asyncio.create_task(self.close())
                        break
                    if not data:
                        await asyncio.sleep(0)
                        continue
                    await self.parse_raw_data(data)

                except Exception as e:
                    # only reached for a broken connection (OSError family, MITM cloud write failing)
                    # or a device that keeps sending packets we cannot handle
                    stats.inc("session_errors")
                    logger.error(f"{lp} Exception in task {name} LOOP, closing session: {e}", exc_info=True)
                    asyncio.create_task(self.close())
                    break
        except asyncio.CancelledError:
            logger.debug(f"{lp} Task {name} CANCELLED cleanly, re-raising...")
            raise

        logger.debug(f"{lp} {name} FINISHED")

    async def read(self, chunk: Optional[int] = None):
        """Read data from the device if there is an open connection"""
        lp = f"{self.lp}read:"
        if self.is_closed() is True:
            logger.debug(f"{lp} Device is closing/closed, exiting read()...")
            return False
        else:
            if chunk is None:
                chunk = STREAM_CHUNK_SIZE
            async with self.read_lock:
                if self.reader:
                    if not self.reader.at_eof():
                        try:
                            raw_data = await self.reader.read(chunk)
                        except (OSError, asyncio.IncompleteReadError) as read_exc:
                            # reset/aborted/TLS error (ssl.SSLError is an OSError): the socket is gone
                            logger.error(f"{lp} Base EXCEPTION: {read_exc}")
                            return False
                        else:
                            return raw_data
                    else:
                        logger.debug(
                            f"{lp} reader is at EOF, setting read socket to None..."
                        )
                        self.reader = None
                else:
                    logger.debug(
                        f"{lp} reader is None/empty -> {self.reader = } // TYPE: {type(self.reader)}"
                    )
                    return False

    async def write(self, data: bytes, broadcast: bool = False) -> Optional[bool]:
        """
        Write data to the device if there is an open connection

        :param data: The raw binary data to write to the device
        :param broadcast: If True, write to all TCP devices connected to the server
        """
        if not isinstance(data, bytes):
            raise ValueError(f"Data must be bytes, not type: {type(data)}")
        if self.is_closed():
            logger.debug(f"{self.lp} Device is closing/closed, can't write data")
        else:
            if self.writer is not None:
                async with self.write_lock:
                    # if broadcast is True:inner_struct__
                    #     # replace queue id with the sending device's queue id
                    #     new_data = bytes2list(data)
                    #     new_data[5:9] = dev.queue_id
                    #     data = bytes(new_data)

                    # check if the underlying writer is closing
                    if self._writer.is_closing():
                        if self.is_closed() is False:
                            # this is probably a connection that was closed by the device (turned off), delete it
                            logger.warning(
                                f"{self.lp} underlying writer is closing but, "
                                f"the device itself hasn't called close(). The device probably "
                                f"dropped the connection (lost power). Removing {self.ip_address}"
                            )
                            off_dev = await g.ncync_server.remove_tcp_device(self)
                            # remove_tcp_device returns None if it was already removed
                            asyncio.create_task((off_dev or self).close())

                        else:
                            logger.debug(
                                f"{self.lp} TCP device is closing, not writing data... "
                            )
                    else:
                        self.writer.write(data)
                        # logger.debug(f"{dev.lp} writing data -> {data}")
                        try:
                            await asyncio.wait_for(self.writer.drain(), timeout=2.0)
                        except TimeoutError as to_exc:
                            logger.error(
                                f"{self.lp} writing data to the device timed out, likely powered off"
                            )
                            raise to_exc
                        else:
                            return True
            else:
                logger.warning(f"{self.lp} writer is None, can't write data!")
            return None

    async def close(self, remove_mitm_button: bool = True):
        lp = f"{self.ip_address}:close:"
        logger.debug(f"{lp} Cancelling device tasks...")
        try:
            self.closing = True
            await self.tasks.cancel_all()
        except Exception as e:
            logger.exception(f"{lp} Exception during device task .cancel_all(): {e}")
        try:
            if self.writer:
                async with self.write_lock:
                    self.writer.close()
                    task = self.writer.wait_closed()
                    await asyncio.wait_for(task, 3.0)
        except (AttributeError, TimeoutError):
            pass
        except Exception as e:
            logger.debug(f"{lp}writer: EXCEPTION: {e}")
        finally:
            self.writer = None

        try:
            if self.reader:
                async with self.read_lock:
                    self.reader.feed_eof()
                    await asyncio.sleep(0.03)
        except AttributeError:
            pass
        except Exception as e:
            logger.exception(f"{lp}reader: EXCEPTION: {e}")
        finally:
            self.reader = None

        # only the node's CURRENT session may delete its switch (a stale session closing after the device reconnected
        # from another IP would delete the new session's switch)
        current = getattr(self.node, "tcp_session", None) if self.node else None
        if self.node and remove_mitm_button and g.mqtt_client and (current is None or current is self):
            await g.mqtt_client.remove_mitm_button(self.node)
        self.closing = False
        self._closed = True
        if self.ip_address in g.ncync_server.tcp_connections:
            # ref
            g_dev = g.ncync_server.tcp_connections[self.ip_address]
            state_closing = self.closing == g_dev.closing
            state_closed = self._closed == g_dev._closed
            if state_closed is False or state_closing is False:
                logger.debug(
                    f"{lp} Mismatch between states in the global device and this device (closed: {state_closed} | closing: {state_closing}), replacing...")
                g.ncync_server.tcp_connections[self.ip_address] = self
            elif g_dev != self:
                logger.debug(f"{lp} Python object mismatch between the global device and this one, replacing...")
                g.ncync_server.tcp_connections[self.ip_address] = self
            # no need
        if self.is_app and self.cloud_writer is not None:
            # a relayed app connection owns its cloud connection: nothing reconnects through this session
            await self.stop_proxy()
        if not self.is_app:
            # the pool just shrank: bulbs the other bridges already reported stale may now meet the vote
            await g.ncync_server.revote_offline()
            # last bridge of its home gone: arm that home's no-bridge timer
            await g.ncync_server.bridge_closed(self)

    @property
    def reader(self):
        return self._reader

    @reader.setter
    def reader(self, value: asyncio.StreamReader):
        self._reader = value

    @property
    def writer(self):
        return self._writer

    @writer.setter
    def writer(self, value: asyncio.StreamWriter):
        self._writer = value

    @property
    def closing(self):
        return self._closing

    @closing.setter
    def closing(self, value: bool):
        self._closing = value

    @property
    def closed(self):
        return self._closed

    @closed.setter
    def closed(self, value: bool):
        self._closed = value

    def is_closed(self):
        if self.closed or self.closing:
            return True
        return False
