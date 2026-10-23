import asyncio
import logging
import logging.handlers
import random
import struct
from typing import Optional

from cync_lan.const import (
    CYNC_LOG_NAME,
    CYNC_MESH_REFRESH_SECS,
    CYNC_RAW,
    DATA_BOUNDARY,
)
from cync_lan.devices.device import CyncDevice
from cync_lan.metadata.model_info import (
    MULTI_ENDPOINT_TYPES,
)
from cync_lan.packet import PacketBuilder
from cync_lan.structs import (
    ConnectionType,
    EntityState,
    GlobalObject,
)
from cync_lan.utils import bytes2list, extract_firmware_dynamically

__all__ = ["PacketHandlersMixin"]
logger = logging.getLogger(CYNC_LOG_NAME)
g = GlobalObject()


class PacketHandlersMixin:
    """Per-packet-type handlers (0x23/43/73/83/A3...) for a CyncTCPSession."""

    async def _dispatch_device_request(
        self,
        pkt_type: int,
        raw_data: bytes,
        packet_data: Optional[bytes],
        queue_id: bytes,
        msg_id: bytes,
        packet_length: int,
        lp: str,
    ):
        """Routes device requests to their specific parsing logic."""
        if pkt_type == 0x23:
            self.queue_id = raw_data[6:10]
            # a device can re-send 0x23; never stack watchers (each would close the session)
            old_watcher = self.tasks.dev_conn_watcher
            if old_watcher is not None and not old_watcher.done():
                old_watcher.cancel()
            self.tasks.dev_conn_watcher = asyncio.create_task(
                self.connection_watcher_task(ConnectionType.device), name=f"connection_watcher-{self.ip_address}"
            )
            logger.debug(
                f"{lp} Device IDENTIFICATION KEY: '{self.queue_id.hex(' ')}'\nRAW HEX: {raw_data.hex(' ')}"
            )
            if not self.mitm_mode:
                await self.write(PacketBuilder.build_23_ack())
                await asyncio.sleep(0.5)
                await self.send_a3()

        elif pkt_type == 0xC3:
            if not self.mitm_mode:
                logger.debug(f"{lp} CONNECTION REQUEST, replying...")
                await self.write(PacketBuilder.build_c3_ack())

        elif pkt_type == 0xD3:
            if not self.mitm_mode:
                await self.write(PacketBuilder.build_d3_ack())

        elif pkt_type == 0xA3:
            logger.debug(
                f"{lp} APP ANNOUNCEMENT packet: {packet_data.hex(' ') if packet_data else 'None'}"
            )
            if not self.mitm_mode:
                ack = PacketBuilder.build_a3_ack(queue_id, bytes(msg_id))
                await self.write(ack)

        elif pkt_type == 0x43:
            await self._handle_43_packet(packet_data, msg_id, packet_length, lp)

        elif pkt_type == 0x83:
            await self._handle_83_packet(
                packet_data, msg_id, packet_header=raw_data[:12], lp=lp
            )

        elif pkt_type == 0x73:
            await self._handle_73_mesh_control(packet_data, queue_id, msg_id, lp)

        elif pkt_type in (0xAB, 0x7B, 0x78):
            pass  # ACKs and other simple responses that don't require parsing or acknowledging receipt

    async def _handle_43_packet(
        self, packet_data: Optional[bytes], msg_id: bytes, packet_length: int, lp: str
    ):
        """Parses timestamps and broadcast status."""
        if packet_data:
            if packet_data[:2] == b"\xc7\x90":
                # --- Timestamp Parsing ---
                ts_idx = 3
                # Gross hack for versions 3.x - 4.x
                ts_end_idx = (
                    -2 if (self.version and 30000 <= self.version <= 40000) else -1
                )
                ts = packet_data[ts_idx:ts_end_idx]

                if ts:
                    ts_ascii = ts.decode("ascii", errors="replace")
                    if ts_ascii[-1] != "," and not ts_ascii[-1].isdigit():
                        ts_ascii = ts_ascii[:-1]

                    logger.debug(
                        f"{lp} Device sent TIMESTAMP -> {ts_ascii} - replying..."
                    )
                    self.device_timestamp = ts_ascii
                else:
                    logger.debug(
                        f"{lp} Could not decode timestamp from: {packet_data.hex(' ')}"
                    )

            else:
                # --- Broadcast Status Parsing ---
                struct_len = 20 if b"\x2e" in packet_data else 19
                extractions = []

                for i in range(0, packet_length, struct_len):
                    extracted = packet_data[i : i + struct_len]
                    if len(extracted) == struct_len:
                        # 02 00 02 = motion broadcast
                        if extracted[:3] == b"\x02\x00\x02":
                            motion_state = extracted[4]
                            if self.node:
                                e_state = self.node.entities.get(0) or next(iter(self.node.entities.values()))

                                # Update state and trigger MQTT broadcast
                                if getattr(e_state, "motion", None) != motion_state:
                                    e_state.motion = motion_state
                                    e_state.recently_seen = 1
                                    await self.node.handle_entity_update(e_state, from_pkt="0x43_motion")

                                logger.debug(f"{lp} Extracted MOTION state: {motion_state} for '{self.node.name}'")

                        else:
                            # Standard power/brightness broadcast logging
                            status_struct = extracted[3:10]
                            status_struct += b"\x01"
                            extractions.append((extracted.hex(" "), list(status_struct)))

                if CYNC_RAW:
                    logger.debug(
                        f"{lp} Extracted data and STATUS struct => {extractions}"
                    )

        # Always ACK a 0x43 ping/status
        if not self.mitm_mode:
            ack = PacketBuilder.build_43_ack(bytes(msg_id))
            await self.write(ack)

    async def _handle_83_packet(
        self, packet_data: Optional[bytes], msg_id: bytes, packet_header: bytes, lp: str
    ):
        """Parses firmware info and 0x7e bound internal status streams."""
        if self.is_app:
            logger.debug(f"{lp} device is app, skipping packet...")
            return

        if not packet_data:
            logger.warning(f"{lp} packet with no data?????")

        else:
            # Unbound Firmware Packet
            if packet_data[0] == 0x00:
                try:
                    fw_type, fw_ver, fw_str = extract_firmware_dynamically(packet_data)
                    if fw_type == "device":
                        self.version, self.version_str = fw_ver, fw_str
                    else:
                        self.protocol_version, self.protocol_version_str = fw_ver, fw_str
                except (IndexError, ValueError, TypeError) as e:
                    logger.debug(f"{lp} exception during firmware parsing: {e}")

            # 0x7e Bound Internal Status
            elif packet_data[0] == DATA_BOUNDARY:
                checksum = packet_data[-2]
                ctrl_bytes = packet_data[5:7]
                # inner_data = packet_data[6:-2]
                inner_data = packet_data[6:-2]
                calc_chksum = sum(inner_data) % 256

                if ctrl_bytes == b"\xfa\xdb" and packet_data[7] == 0x13:
                    await self._parse_83_device_state(
                        packet_data, checksum, calc_chksum, lp
                    )
                elif ctrl_bytes == b"\xfa\x54":
                    await self._parse_83_motion_state(packet_data, lp)
                elif ctrl_bytes == b"\xfa\xd9":
                    # seems to be some sort of bulk status msg. seen when updating devices firmware,
                    # it seemed to broadcast each devices percentage complete status
                    devices = []
                    try:
                        device_count = packet_data[9]
                        # Devices start at index 10, each block is 4 bytes
                        idx = 10
                        for _ in range(device_count):
                            dev_id = packet_data[idx]
                            sub_id = packet_data[idx + 1]
                            status_type = packet_data[idx + 2]
                            value = packet_data[idx + 3]
                            devices.append({
                                "node_id": dev_id, "sub_id": sub_id,
                                "type": status_type, "value": value
                            })
                            idx += 4
                        logger.debug(f"{lp} bulk status: {devices}")
                    except IndexError:
                        logger.debug(f"{lp} truncated bulk status packet, ignoring")
                else:
                    logger.warning(
                        f"{lp} UNKNOWN packet data (ctrl_bytes: {ctrl_bytes.hex(' ')} // checksum valid: "
                        f"{checksum == calc_chksum})\n\nHEX: {packet_data[1:-1].hex(' ')}\nINT: {list(packet_data[1:-1])}"
                    )

        if not self.mitm_mode:
            await self.write(PacketBuilder.build_83_ack(msg_id))

    async def _parse_83_device_state(
        self, packet_data: bytes, checksum: int, calc_chksum: int, lp: str
    ):
        if len(packet_data) < 26:
            raise ValueError("Packet too short for standard status update")
        try:
            dev_id = packet_data[14]
            recently_seen, power, bri, tmp, r, gr, b = struct.unpack(">BBBBBBB", packet_data[19:26])
            parsed_state = EntityState(
                **{
                    "name": "",
                    "dev_id": dev_id,
                    "recently_seen": recently_seen,
                    "power": power,
                    "brightness": bri,
                    "temperature": tmp,
                    "red": r,
                    "green": gr,
                    "blue": b,
                }
            )
        except struct.error as e:
            logger.error(f"{lp} Failed to unpack status packet: {e}")
            return

        cync_device: CyncDevice = g.ncync_server.node_devices.get(dev_id)
        if not cync_device:
            logger.warning(
                f"{lp} Received internal STATUS for unknown device [group/room?, safe to ignore]: {parsed_state}"
            )
            return
        # type 96 recently_seen is actually the motion state
        if cync_device and cync_device.type == 96:
            parsed_state.motion = recently_seen
            recently_seen = 1


        if cync_device.type in MULTI_ENDPOINT_TYPES:
            if cync_device.type == 67:
                # bri used as bitmask
                for e_state_ in cync_device.entities.values():
                    bit_shift = e_state_.sub_id - 1
                    e_state_.power = (
                        1 if (parsed_state.brightness & (1 << bit_shift)) else 0
                    )
                    e_state_.recently_seen = recently_seen
                    logger.debug(f"{lp} Internal STATUS for {e_state_}")
                    await cync_device.handle_entity_update(e_state_, from_pkt="0x83", bridge_ip=self.ip_address)
        else:
            parsed_state.name = cync_device.name
            logger.debug(f"{lp} Internal STATUS for {parsed_state}")
            await cync_device.handle_entity_update(
                parsed_state, from_pkt="0x83", bridge_ip=self.ip_address
            )

        # Checksum Stream Logic, the LED light controller sends 0x83 in a stream of data with checksum mismatches
        # if list(packet_data[9:12]) == [17, 17, 17]:
        #     if self.first_83_packet_checksum is None:
        #         self.first_83_packet_checksum = checksum
        #         if calc_chksum != checksum:
        #             logger.warning(
        #                 f"{lp} [LED Controller?] Checksum mismatch in INITIAL STATUS STREAM - FIRST packet data [safe to ignore]..."
        #             )
        #     else:
        #         if checksum == self.first_83_packet_checksum:
        #             calc_chksum = self.first_83_packet_checksum
        #         else:
        #             self.first_83_packet_checksum = None
        #
        # if calc_chksum != checksum:
        #     pass

    async def _parse_83_motion_state(self, packet_data: bytes, lp: str):
        if len(packet_data) < 16:
            return

        dev_id = packet_data[9]
        motion_flag = packet_data[15]

        cync_device = g.ncync_server.node_devices.get(dev_id)
        if not cync_device:
            return

        e_state = cync_device.entities.get(0, next(iter(cync_device.entities.values())))
        e_state.motion = motion_flag
        e_state.recently_seen = 1

        await cync_device.handle_entity_update(e_state, from_pkt="0x83_fa54")


    async def _handle_73_mesh_control(
        self, packet_data: Optional[bytes], queue_id: bytes, msg_id: bytes, lp: str
    ):
        """Parses mesh info arrays and fires callbacks for control acknowledgements."""
        if self.is_app:
            logger.debug(f"{lp} device is app, skipping packet...")
            return

        if not packet_data:
            logger.warning(f"{lp} packet with no data?!?")
        else:
            if packet_data[0] == DATA_BOUNDARY:
                ctrl_bytes = packet_data[5:7]
                end_bndry_idx = packet_data[1:].find(DATA_BOUNDARY) + 1
                inner_struct = packet_data[1:end_bndry_idx]

                if ctrl_bytes == b"\xf9\x52":
                    await self._process_73_mesh_info(inner_struct, queue_id, lp)

                elif ctrl_bytes[0] == 0xF9 and ctrl_bytes[1] in (0xD0, 0xF0, 0xE2):
                    # Handle Callbacks for control messages
                    ctrl_msg_id = packet_data[1]
                    success = packet_data[7] == 1
                    msg = self.messages.control.pop(ctrl_msg_id, None)

                    if success and msg:
                        if callable(msg.callback):
                            await msg.callback()
                        else:
                            await msg.callback
                        # logger.debug(f"{lp} Received a command success reply: {msg}")
                    elif success and not msg:
                        logger.debug(
                            f"{lp} CONTROL packet ACK callback NOT found for msg ID: {ctrl_msg_id}"
                        )

                elif ctrl_bytes == b"\xfa\x8e":
                    if packet_data[1] == 0x00:
                        try:
                            fw_type, fw_ver, fw_str = extract_firmware_dynamically(
                                packet_data[1:-1]
                            )
                            if fw_type == "device":
                                self.version, self.version_str = fw_ver, fw_str
                            else:
                                self.protocol_version, self.protocol_version_str = fw_ver, fw_str
                        except (IndexError, ValueError, TypeError) as e:
                            logger.debug(f"{lp} Exception during firmware parsing: {e}")

        if not self.mitm_mode:
            # logger.debug(f"DBG>>>> Queue ID = {queue_id.hex(' ')}")
            await self.write(PacketBuilder.build_73_ack(self.queue_id, msg_id))

    async def _process_73_mesh_info(
        self, inner_struct: bytes, queue_id: bytes, lp: str
    ):
        """Handles the 24-byte paginated mesh info loop."""
        if len(inner_struct) < 15:
            return

        minfo_start_idx = 14
        minfo_length = 24
        if inner_struct[minfo_start_idx] == 0x00:
            minfo_start_idx += 1
        if inner_struct[minfo_start_idx] == 0x00:
            logger.error(
                f"{lp}mesh: dev_id is 0 when using index: {minfo_start_idx}, skipping..."
            )
            return

        packet_devices = inner_struct[8]
        total_devices = inner_struct[12]
        if getattr(self, "_mesh_expected", 0) == 0 or getattr(
            self, "_mesh_received", 0
        ) >= getattr(self, "_mesh_expected", 0):
            self._mesh_expected = total_devices
            self._mesh_received = 0
            logger.debug(
                f"{lp} Starting new MeshInfo parsing sequence. Expecting {total_devices} total devices."
            )
        self._mesh_received += packet_devices

        loop_num = 0
        for i in range(minfo_start_idx, len(inner_struct), minfo_length):
            loop_num += 1
            mesh_dev_struct = inner_struct[i : i + minfo_length]
            if len(mesh_dev_struct) < minfo_length:
                continue

            dev_id = mesh_dev_struct[0]
            dev_type_id = mesh_dev_struct[2]
            dev_state, dev_bri, dev_tmp = (
                mesh_dev_struct[8],
                mesh_dev_struct[12],
                mesh_dev_struct[16],
            )
            dev_r, dev_g, dev_b = mesh_dev_struct[20:23]

            if dev_state == 0 and dev_bri > 0:
                dev_bri = 0

            node_repr: Optional["CyncDevice"] = g.ncync_server.node_devices.get(dev_id)
            if node_repr:
                dev_name = node_repr.name
                if loop_num == 1:
                    # byte 3 (idx 2) is a device type byte but,
                    # it only reports on the first item (itself)
                    # convert to int, and it is the same as deviceType from cloud.
                    if not self.node:
                        self.node = node_repr
                        self.node.tcp_session = self
                        self.name = node_repr.name
                        self.lp = f"{self.ip_address}[{self.node.id}]:"
                        logger.debug(
                            f"{self.lp}0x73: Setting TCP"
                            f" Node ID to: {self.node.id}"
                        )
                        self.capture_info()
                        # dynamically add the MITM mode button for nodes that are connected via TCP
                        self.mitm_button_added = True
                        await g.mqtt_client.add_mitm_button(node_repr)
                        # check mqtt mitm button retain state
                        payload = await g.mqtt_client.get_startup_topic_state(
                            f"{g.mqtt_client.topic}/status/{node_repr.home_id}-{node_repr.id}/mitm")
                        if payload is not None:
                            # Find the TCP device instance and trigger start/stop
                            tcp_pool = g.ncync_server.get_dev_tcp_pool_sync()
                            for tcp_dev in tcp_pool:
                                if tcp_dev.node:
                                    if tcp_dev.node.id == self.node.id:
                                        if payload.upper() == "ON":
                                            await tcp_dev.start_mitm()

                    elif self.node:
                        if self.mitm_button_added is False:
                            self.mitm_button_added = True
                            await g.mqtt_client.add_mitm_button(node_repr)
                        if self.node.id != dev_id:
                            logger.warning(
                                f"{self.lp}0x73: node_id MISMATCH "
                                f"open an issue on github. current: {self.node.id} "
                                f"// proposed: {dev_id}"
                            )
                    lp = f"{self.lp}0x73:"
                    if dev_type_id:
                        self.device_type_id = dev_type_id
                    self.name = dev_name

                if node_repr.type in MULTI_ENDPOINT_TYPES:
                    if node_repr.type == 67:
                        # bri byte is a bitmask for on/off state of endpoints
                        # since we know the state of up to 8 endpoints at once, parse them all
                        for e_state_ in node_repr.entities.values():
                            bit_shift = e_state_.sub_id - 1
                            e_state_.power = 1 if (dev_bri & (1 << bit_shift)) else 0
                            e_state_.recently_seen = 1
                            logger.debug(
                                f"{lp} MeshInfo for {node_repr.name} - {e_state_}"
                            )
                            await node_repr.handle_entity_update(
                                e_state_,
                                from_pkt="0x73",
                            )
                else:
                    # Standard single endpoint
                    e_state = EntityState(
                        name=node_repr.name,
                        dev_id=dev_id,
                        power=dev_state,
                        brightness=dev_bri,
                        temperature=dev_tmp,
                        red=dev_r,
                        green=dev_g,
                        blue=dev_b,
                    )
                    logger.debug(f"{lp} MeshInfo for {e_state}")
                    await node_repr.handle_entity_update(
                        e_state,
                        from_pkt="0x73",
                    )

            else:
                logger.warning(
                    f"{lp} Received MeshInfo for unknown device ID: "
                    f"{dev_id} -> You need to export a new config file from the cloud!"
                )

        if not self.mitm_mode:
            mesh_ack = PacketBuilder.build_mesh_status_ack(self.queue_id)
            await self.write(mesh_ack)

        if getattr(self, "_mesh_received", 0) >= getattr(self, "_mesh_expected", 0):
            self._mesh_expected = 0
            self._mesh_received = 0

    async def ask_for_mesh_info(self):
        """
        Ask the device for mesh info. As far as I can tell, this will return whatever
        devices are connected to the device you are querying. It may also trigger
        the device to send its own status packet.
        """
        lp = f"{self.lp}"
        if self.mitm_mode:
            logger.debug(
                f"{lp} MITM Mode active, not writing to the Cync TCP device..."
            )
            return
        if len(self.queue_id) != 4:
            logger.warning(f"{lp} queue_id is not initialized, skipping mesh info request")
            return
        mesh_info_data = PacketBuilder.build_mesh_info_request(self.queue_id)
        _rdmsg = ""
        if CYNC_RAW is True:
            _rdmsg = f"\nBYTES: {mesh_info_data}\nHEX: {mesh_info_data.hex(' ')}\nINT: {bytes2list(mesh_info_data)}"
        logger.debug(f"{lp} Requesting ALL device(s) MeshInfo{_rdmsg}")
        try:
            await self.write(mesh_info_data)
        except TimeoutError as to_exc:
            logger.error(
                f"{lp} Requesting ALL device(s) status timed out, likely powered off"
            )
            raise to_exc
        except OSError as e:
            logger.error(f"{lp} writing the mesh info request failed: {e!r}")

    async def mesh_refresh_task(self, interval: float):
        """
        Re-request mesh info every `interval` seconds. A bridge reports 0x83 status changes (including the stale flag
        the offline vote counts) only for a few minutes after it was asked for mesh info, which normally happens once,
        on connect. Without this, a bulb cut at the wall later on is never reported stale and stays "on". [inferred,
        baudneo/cync-lan#39]
        """
        lp = f"{self.lp}mesh_refresh:"
        try:
            while True:
                await asyncio.sleep(interval)
                if self.is_closed():
                    break
                await self.ask_for_mesh_info()
        except asyncio.CancelledError:
            logger.debug(f"{lp} CANCELLED cleanly, re-raising")
            raise
        except TimeoutError:
            # ask_for_mesh_info already logged it; the connection watcher tears the session down
            pass

    def start_mesh_refresh(self, interval: float = CYNC_MESH_REFRESH_SECS):
        if interval <= 0 or self.mitm_mode:
            return
        old = self.tasks.mesh_refresh
        if old is not None and not old.done():
            old.cancel()
        self.tasks.mesh_refresh = asyncio.create_task(
            self.mesh_refresh_task(interval), name=f"mesh_refresh-{self.ip_address}"
        )

    async def send_a3(self):
        """
        The device will not be controllable until this messagee is sent,
        we also request the known BTLE mesh device ID's and state
        """
        # random 2 bytes + padded byte
        rand_bytes = self.xa3_msg_id = random.getrandbits(16).to_bytes(2, "big")
        rand_bytes += bytes([0x00])
        if len(self.queue_id) != 4:
            logger.warning(f"{self.lp} queue_id is not initialized, skipping 0xA3 control request")
            return
        a3_packet = PacketBuilder.build_a3_control_request(self.queue_id, rand_bytes)
        logger.debug(f"{self.lp} Sending 0xA3 (want to control) packet...")
        await self.write(a3_packet)
        self.ready_to_control = True
        self.xa3_msg_id += random.getrandbits(8).to_bytes(1, "big")
        # send mesh info request
        await asyncio.sleep(1.5)
        await self.ask_for_mesh_info()
        self.start_mesh_refresh()
