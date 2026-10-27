import asyncio
import datetime
import logging
import logging.handlers
import time
from typing import List, Optional

from cync_lan import __version__
from cync_lan.capture import CaptureWriter, pii_patterns
from cync_lan.const import (
    CYNC_ACCOUNT_PASSWORD,
    CYNC_ACCOUNT_USERNAME,
    CYNC_CAPTURE_DIR,
    CYNC_CAPTURE_FILE_MAX_MB,
    CYNC_CAPTURE_MAX_MB,
    CYNC_CAPTURE_SANITIZE,
    CYNC_LOG_NAME,
    CYNC_RAW,
    CYNC_SECRET_KEY,
    STREAM_CHUNK_SIZE,
)
from cync_lan.devices.device import CyncDevice
from cync_lan.devices.handlers import PacketHandlersMixin
from cync_lan.devices.proxy import ProxyMixin
from cync_lan.packet import PacketBuilder
from cync_lan.packet.framer import PacketFramer
from cync_lan.stats import stats
from cync_lan.structs import (
    ConnectionType,
    GlobalObject,
    MessageCache,
    Tasks,
)
from cync_lan.utils import bytes2list, format_socat_style

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
    ):
        if not ip_address:
            raise ValueError(
                f"A valid IP address must be provided to {CyncTCPSession.__class__.__name__} constructor"
            )
        self.lp = f"{ip_address}:"
        self.tasks = Tasks()
        self.framer = PacketFramer()
        self.bad_packets = 0
        self.capture: Optional[CaptureWriter] = None
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
        self.capture = self._new_capture()  # needs ip_address, so it comes last


    async def existing_init(self):
        """Used when replacing an existing TCP connection, when a device reconnects"""
        lp = f"{self.lp}existing init:"
        # new socket: any half-received packet from the old one is meaningless
        self.framer.reset()
        self.bad_packets = 0
        self.capture = self._new_capture()  # a new socket is a new capture file
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
        if self.mitm_mode is True:
            logger.debug(f"{lp} MITM mode is active, making sure the proxy is started...")
            if self.node:
                await g.mqtt_client.add_mitm_button(self.node)
            if not self.is_proxy_good():
                await self.stop_proxy()
                await asyncio.sleep(0.25)
                await self.start_proxy()
            else:
                logger.debug(f"{lp} Proxy connection is up!")


    def _new_capture(self) -> Optional[CaptureWriter]:
        """A recorder for this connection when CYNC_CAPTURE_DIR is set, else None."""
        if not CYNC_CAPTURE_DIR:
            return None
        writer = CaptureWriter(
            CYNC_CAPTURE_DIR,
            self.ip_address or "unknown",
            version=__version__,
            sanitize=CYNC_CAPTURE_SANITIZE,
            patterns=self._pii_patterns() if CYNC_CAPTURE_SANITIZE else (),
            file_max_bytes=CYNC_CAPTURE_FILE_MAX_MB * 1024 * 1024,
            dir_max_bytes=CYNC_CAPTURE_MAX_MB * 1024 * 1024,
        )
        return writer if writer.active else None

    def _pii_patterns(self):
        """Everything we know that must not appear in a capture: from the user's own config and account."""
        server = getattr(g, "ncync_server", None)
        nodes = list(server.node_devices.values()) if server else []
        return pii_patterns(
            macs=[m for n in nodes for m in (getattr(n, "mac", None), getattr(n, "wifi_mac", None))],
            home_ids={n.home_id for n in nodes if n.home_id},
            secrets=[CYNC_ACCOUNT_USERNAME, CYNC_ACCOUNT_PASSWORD, CYNC_SECRET_KEY],
            ips=[self.ip_address] if self.ip_address else [],
        )

    def capture_info(self) -> None:
        """Record what we have learned about this device so far (type, firmware, node ids -> types)."""
        cap = self.capture
        if cap is None or not cap.active:
            return
        server = getattr(g, "ncync_server", None)
        # ids, types and endpoint ids only: no names, MACs or home ids
        nodes = (
            {str(i): {"type": n.type, "endpoints": sorted(n.entities or {})} for i, n in server.node_devices.items()}
            if server
            else None
        )
        cap.info(
            node_id=self.node.id if self.node else None,
            device_type=self.node.type if self.node else None,
            device_type_id=self.device_type_id,
            firmware=self.version_str,
            firmware_num=self.version,
            protocol=self.protocol_version_str,
            nodes=nodes,
        )

    def _end_capture(self, reason: str) -> None:
        cap, self.capture = self.capture, None
        if cap is None:
            return
        if self.is_app:
            cap.discard()  # app sessions carry account tokens: never keep them
            return
        self.capture = cap
        self.capture_info()
        self.capture = None
        cap.close(reason)

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
        if self.mitm_mode:
            # Log for devices or log for apps only if global toggle is ON
            if self.cloud_writer:
                should_log = not self.is_app or g.env.app_mitm_logging
                if should_log and self.mitm_logger:
                    self.mitm_logger.debug(
                        format_socat_style(
                            data, "to_cloud", self.ip_address, self.mitm_bytes_to_cloud
                        )
                    )
                self.cloud_writer.write(data)
                await self.cloud_writer.drain()
                self.mitm_bytes_to_cloud += len(data)
            else:
                logger.warning(
                    f"{lp} MITM mode enabled but the cloud writer is: {self.cloud_writer}"
                )
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
            try:
                await self.parse_packet(extracted_packet)
            except (OSError, TimeoutError, asyncio.IncompleteReadError):
                # the connection itself is broken: let receive_task tear the session down
                raise
            except Exception as exc:
                # a handler bug / odd packet must cost one packet, not the device connection
                self.bad_packets += 1
                stats.inc("packets_failed")
                logger.error(
                    f"{lp} dropping packet that failed to parse ({self.bad_packets} in a row): "
                    f"{exc!r}\nPACKET: {extracted_packet.hex(' ')}",
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
            if self.allowed_to_connect is False and await self.can_connect() is False:
                # rejected: the socket was closed, don't answer the packet with writer=None
                return
            await self._dispatch_device_request(
                pkt_type, data, packet_data, queue_id, msg_id, packet_length, lp
            )
        elif PacketBuilder.is_app_request(pkt_type):

            if not self.is_app:
                logger.info(
                    f"{lp} Device has been identified as the Cync mobile app, enabling proxying to the Cync cloud for all App connections..."
                )
                self.is_app = True
                self._end_capture("app session")
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
                        if self.capture is not None and ctrl_msg.cmd:
                            self.capture.ack(ctrl_msg.cmd, msg_id=ctrl_msg_id, ok=None, reason="timeout")
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
                    if self.capture is not None:
                        self.capture.rx(data)
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

    async def write(self, data: bytes, broadcast: bool = False, cmd: Optional[dict] = None) -> Optional[bool]:
        """
        Write data to the device if there is an open connection

        :param data: The raw binary data to write to the device
        :param broadcast: If True, write to all TCP devices connected to the server
        :param cmd: capture tag describing the command in ``data`` (never sent to the device)
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
                            if self.capture is not None:
                                self.capture.tx(data, cmd)
                            return True
            else:
                logger.warning(f"{self.lp} writer is None, can't write data!")
            return None

    async def close(self, remove_mitm_button: bool = True):
        lp = f"{self.ip_address}:close:"
        logger.debug(f"{lp} Cancelling device tasks...")
        self._end_capture("closed")
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

        if self.node and remove_mitm_button and g.mqtt_client:
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
        if not self.is_app:
            # the pool just shrank: bulbs the other bridges already reported stale may now meet the vote
            await g.ncync_server.revote_offline()

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
