import asyncio
import json
import logging
import random
import re
from json import JSONDecodeError
from typing import Coroutine, Dict, List, Optional, Union

import aiomqtt

from cync_lan.const import (
    CYNC_BRIDGE_DEVICE_REGISTRY_CONF,
    CYNC_BRIDGE_OBJ_ID,
    CYNC_HASS_BIRTH_MSG,
    CYNC_HASS_STATUS_TOPIC,
    CYNC_HASS_TOPIC,
    CYNC_HASS_WILL_MSG,
    CYNC_LOG_NAME,
    CYNC_MANUFACTURER,
    CYNC_MAXK,
    CYNC_MINK,
    CYNC_MQTT_CONN_DELAY,
    CYNC_MQTT_HOST,
    CYNC_MQTT_PASS,
    CYNC_MQTT_PORT,
    CYNC_MQTT_USER,
    CYNC_TOPIC,
    CYNC_VERSION,
    DEVICE_LWT_MSG,
    FACTORY_EFFECTS_BYTES,
    MQTT_DEAD,
    MQTT_DEBUG,
    ORIGIN_STRUCT,
)
from cync_lan.devices import CyncDevice
from cync_lan.metadata.model_info import device_type_map, DeviceClassification
from cync_lan.structs import EntityState, FanSpeed, GlobalObject
from cync_lan.utils import send_sigterm

logger = logging.getLogger(CYNC_LOG_NAME)
g = GlobalObject()
bridge_device_reg_struct = CYNC_BRIDGE_DEVICE_REGISTRY_CONF
# Log all loggers in the logger manager
# logging.getLogger().manager.loggerDict.keys()


class MQTTClient:
    lp: str = "mqtt:"
    cync_topic: str
    start_task: Optional[asyncio.Task] = None

    _instance: Optional["MQTTClient"] = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        self._connected = False
        self.tasks: Optional[List[Union[asyncio.Task, Coroutine]]] = None
        lp = f"{self.lp}init:"
        if not CYNC_TOPIC:
            topic = "cync_lan"
            logger.warning("%s MQTT topic not set, using default: %s" % (lp, topic))
        else:
            topic = CYNC_TOPIC

        if not CYNC_HASS_TOPIC:
            ha_topic = "homeassistant"
            logger.warning(
                "%s HomeAssistant topic not set, using default: %s" % (lp, ha_topic)
            )
        else:
            ha_topic = CYNC_HASS_TOPIC

        self.broker_client_id = f"cync_lan_{g.uuid}"
        lwt = aiomqtt.Will(topic=f"{topic}/connected", payload=DEVICE_LWT_MSG)
        self.broker_host = CYNC_MQTT_HOST
        self.broker_port = CYNC_MQTT_PORT
        self.broker_username = CYNC_MQTT_USER
        self.broker_password = CYNC_MQTT_PASS
        self.client = aiomqtt.Client(
            hostname=self.broker_host,
            port=int(self.broker_port),
            username=self.broker_username,
            password=self.broker_password,
            identifier=self.broker_client_id,
            will=lwt,
            # logger=logger,
        )

        self.topic = topic
        self.ha_topic = ha_topic

    async def start(self):
        itr = 0
        lp = f"{self.lp}start:"
        try:
            while True:
                itr += 1
                self._connected = await self.connect()
                if self._connected:
                    # ["state_topic"] = f"{self.topic}/status/bridge/mqtt_client/connected"
                    await self.publish(
                        f"{self.topic}/status/bridge/mqtt_client/connected",
                        "ON".encode(),
                    )

                    if itr == 1:
                        logger.debug(f"{lp} Seeding all devices: offline")
                        for device_id, node in g.ncync_server.node_devices.items():
                            # if device.is_fan_controller:
                            #     logger.debug(f"{lp} TESTING>>> Setting up fan controller for device: {device.name} (ID: {device.id})")
                            #     # set device online for testing
                            #     await self.pub_online(device.id, True)
                            #     await device.set_brightness(50)  # set brightness to 50% for testing
                            # else:
                            await self.pub_online(device_id, False)
                    elif itr > 1:
                        tasks = []
                        # set the device online/offline and set its status
                        for node in g.ncync_server.node_devices.values():
                            # key is entity id (sub_id), value is state class which has node and endpoint id
                            # map is for easy lookup based on endpoint id, rather than iterating a list of endpoints
                            for epoint_state in node.entities.values():
                                tasks.append(self.pub_online(node.id, node.online))
                                tasks.append(
                                    self.parse_entity_state(
                                        epoint_state,
                                        from_pkt="'re-connect'",
                                    )
                                )
                        if tasks:
                            await asyncio.gather(*tasks)
                    logger.debug(f"{lp} Starting MQTT receiver...")
                    lp: str = f"{self.lp}rcv:"
                    # todo: monitor current endpoint state in MQTT? use for syncing?
                    topics = [
                        (f"{self.topic}/set/#", 0),
                        (f"{self.ha_topic}/status", 0),
                    ]
                    await self.client.subscribe(topics) if not MQTT_DEAD else None
                    logger.debug(
                        f"{lp} Subscribed to MQTT topics: {[x[0] for x in topics]}. "
                        f"Waiting for MQTT messages..."
                    )
                    try:
                        await self.start_receiver_task()
                    except asyncio.CancelledError as ce:
                        logger.debug(
                            f"{lp} MQTT receiver task cancelled, propagating..."
                        )
                        raise ce
                    except (aiomqtt.MqttError, aiomqtt.MqttCodeError) as msg_err:
                        logger.warning(f"{lp} MQTT error: {msg_err}")
                        continue
                else:
                    await self.publish(
                        f"{self.topic}/status/bridge/mqtt_client/connected",
                        "OFF".encode(),
                    )
                    delay = CYNC_MQTT_CONN_DELAY
                    if delay is None or delay <= 0:
                        logger.debug(
                            f"{lp} MQTT connection delay is less than or equal to 0, which is probably a typo, setting to 5..."
                        )
                        delay = 5

                    logger.info(
                        f"{lp} connecting to MQTT broker failed, sleeping for {delay} seconds before re-trying..."
                    )
                    await asyncio.sleep(delay)
        except asyncio.CancelledError as ce:
            raise ce
        except Exception as exc:
            logger.exception(f"{lp} MQTT start() EXCEPTION: {exc}")

    async def connect(self) -> bool:
        lp = f"{self.lp}connect:"
        self._connected = False
        logger.debug(f"{lp} Connecting to MQTT broker...")
        lwt = aiomqtt.Will(topic=f"{self.topic}/connected", payload=DEVICE_LWT_MSG)
        g.reload_env()
        self.broker_host = g.env.mqtt_host
        self.broker_port = g.env.mqtt_port
        self.broker_username = g.env.mqtt_user
        self.broker_password = g.env.mqtt_pass
        self.client = aiomqtt.Client(
            hostname=self.broker_host,
            port=int(self.broker_port),
            username=self.broker_username,
            password=self.broker_password,
            identifier=self.broker_client_id,
            will=lwt,
            # logger=logger,
        )
        try:
            await self.client.__aenter__()
        except aiomqtt.MqttError as mqtt_err_exc:
            # -> [Errno 111] Connection refused
            # [code:134] Bad user name or password
            logger.error(f"{lp} Connection failed [MqttError] -> {mqtt_err_exc}")
            if "code:134" in str(mqtt_err_exc):
                logger.error(
                    f"{lp} Bad username or password, check your MQTT credentials (username: {g.env.mqtt_user})"
                )
                send_sigterm()
        else:
            self._connected = True
            logger.info(
                f"{lp} Connected to MQTT broker: {self.broker_host} port: {self.broker_port}"
            )
            await self.send_birth_msg()
            await asyncio.sleep(1)
            await self.homeassistant_discovery()
            return True
        return False

    async def start_receiver_task(self):
        """Start listening for MQTT messages on subscribed topics"""
        lp = f"{self.lp}rcv:"
        async for message in self.client.messages:
            message: aiomqtt.message.Message
            topic = message.topic
            payload = message.payload
            if (payload is None) or (payload is not None and not payload):
                logger.debug(
                    f"{lp} Received empty/None payload ({payload}) for topic: {topic} , skipping..."
                )
                continue
            _topic = topic.value.split("/")
            tasks = []
            node = None
            sub_id: Optional[int] = None
            # logger.debug(f"{lp} RECEIVED MQTT TOPIC: {topic} // MESSAGE: {payload}")
            if _topic[0] == CYNC_TOPIC:
                if _topic[1] == "set":
                    # TOPIC: cync_lan_TEST/set/769962427-46/mitm // MESSAGE: b'ON'
                    device_uuid_ = _topic[2]
                    # homeID-deviceID-childID / no -childID when no children
                    _ids = device_uuid_.split("-")
                    _home_id = _ids[0]
                    device_id = int(_ids[1])
                    if len(_ids) >= 3:
                        sub_id = int(_ids[-1])

                    extra_data = _topic[3:] if len(_topic) > 3 else None
                    if device_uuid_ == "bridge":
                        pass
                    else:
                        if device_id not in g.ncync_server.node_devices:
                            logger.warning(
                                f"{lp} Device ID {device_id} not found, device is disabled in config file or have you deleted / added any "
                                f"devices recently?"
                            )
                            continue
                        node: CyncDevice = g.ncync_server.node_devices[device_id]
                    # bridge or fan, extra data
                    if extra_data:
                        norm_pl = payload.decode().casefold()
                        # logger.debug(f"{lp} Extra data found: {extra_data}")
                        if extra_data[0] == "app_logging":
                            # Determine the new state
                            is_on = payload.decode().upper() == "ON"

                            # Update the global state
                            g.env.app_mitm_logging = is_on

                            # Publish the new status back to MQTT
                            await self.publish(
                                f"{self.topic}/status/bridge/app_logging", payload
                            )
                            logger.info(
                                f"{lp} Global App MITM Logging set to {'ON' if is_on else 'OFF'}"
                            )
                        elif extra_data[0] == "mitm":
                            is_on = payload.decode().upper() == "ON"
                            # Find the TCP device instance and trigger start/stop
                            for tcp_dev in g.ncync_server.tcp_connections.values():
                                if tcp_dev.node_id == node.id:
                                    if is_on:
                                        await tcp_dev.start_mitm()
                                    else:
                                        logger.debug(
                                            "DBG>>> MITM mqtt command is calling mitm_stop()"
                                        )
                                        await tcp_dev.stop_mitm()
                            await self.publish(
                                f"{self.topic}/status/{device_uuid_}/mitm", payload
                            )
                        elif extra_data[0] == "restart":
                            if norm_pl == "press":
                                logger.info(
                                    f"{lp} Restart button pressed! Restarting Cync LAN bridge (NOT IMPLEMENTED)..."
                                )
                        elif extra_data[0] == "start_export":
                            if norm_pl == "press":
                                logger.info(
                                    f"{lp} Start Export button pressed! Starting Cync Export (NOT IMPLEMENTED)..."
                                )
                        elif extra_data[0] == "otp":
                            if extra_data[1] == "submit":
                                logger.info(
                                    f"{lp} OTP submit button pressed! (NOT IMPLEMENTED)..."
                                )
                            elif extra_data[1] == "input":
                                logger.info(
                                    f"{lp} OTP input received: {norm_pl} (NOT IMPLEMENTED)..."
                                )
                        elif node and node.is_fan_controller:
                            if extra_data[0] == "percentage":
                                percentage = int(norm_pl)
                                if percentage == 0:
                                    tasks.append(node.set_brightness(0))
                                elif percentage <= 25:
                                    logger.debug(
                                        f"{lp} Fan percentage received: {percentage}, translated to: 'low' preset"
                                    )
                                    tasks.append(node.set_brightness(25))
                                elif percentage <= 50:
                                    logger.debug(
                                        f"{lp} Fan percentage received: {percentage}, translated to: 'medium' preset"
                                    )
                                    tasks.append(node.set_brightness(50))
                                elif percentage <= 75:
                                    logger.debug(
                                        f"{lp} Fan percentage received: {percentage}, translated to: 'high' preset"
                                    )
                                    tasks.append(node.set_brightness(75))
                                elif percentage <= 100:
                                    logger.debug(
                                        f"{lp} Fan percentage received: {percentage}, translated to: 'max' preset"
                                    )
                                    tasks.append(node.set_brightness(100))
                                else:
                                    logger.warning(
                                        f"{lp} Fan percentage received: {percentage} is out of range (0-100), skipping..."
                                    )
                            elif extra_data[0] == "preset":
                                preset_mode = norm_pl
                                if preset_mode == "off":
                                    tasks.append(node.set_fan_speed(FanSpeed.OFF))
                                elif preset_mode == "low":
                                    tasks.append(node.set_fan_speed(FanSpeed.LOW))
                                elif preset_mode == "medium":
                                    tasks.append(node.set_fan_speed(FanSpeed.MEDIUM))
                                elif preset_mode == "high":
                                    tasks.append(node.set_fan_speed(FanSpeed.HIGH))
                                elif preset_mode == "max":
                                    tasks.append(node.set_fan_speed(FanSpeed.MAX))
                                else:
                                    logger.warning(
                                        f"{lp} Unknown preset mode: {preset_mode}, skipping..."
                                    )

                    else:
                        if payload.startswith(b"{"):
                            try:
                                json_data = json.loads(payload)
                            except JSONDecodeError as e:
                                logger.error(
                                    "%s bad json message: {%s} EXCEPTION => %s"
                                    % (lp, payload, e)
                                )
                                continue
                            except Exception as e:
                                logger.error(
                                    "%s error will decoding a string into JSON: '%s' EXCEPTION => %s"
                                    % (lp, payload, e)
                                )
                                continue

                            if "state" in json_data and "brightness" not in json_data:
                                if "effect" in json_data:
                                    effect = json_data["effect"]
                                    tasks.append(node.set_lightshow(effect, sub_id))
                                else:
                                    if json_data["state"].upper() == "ON":
                                        tasks.append(node.set_power(1, sub_id))
                                    else:
                                        tasks.append(node.set_power(0, sub_id))
                            if "brightness" in json_data:
                                lum = int(json_data["brightness"])
                                tasks.append(node.set_brightness(lum, sub_id))

                            if "color_temp" in json_data:
                                tasks.append(
                                    node.set_temperature(
                                        self.kelvin2cync(int(json_data["color_temp"])),
                                        sub_id,
                                    )
                                )
                            elif "color" in json_data:
                                color = []
                                for rgb in ("r", "g", "b"):
                                    if rgb in json_data["color"]:
                                        color.append(int(json_data["color"][rgb]))
                                    else:
                                        color.append(0)
                                if sub_id is not None:
                                    color.append(sub_id)
                                tasks.append(node.set_rgb(*color))
                        # binary payload does not start with a '{', so it is not JSON
                        else:
                            str_payload = payload.decode("utf-8").strip()
                            #  use a regex pattern to determine if it is a single word
                            pattern = re.compile(r"^\w+$")
                            if pattern.match(str_payload):
                                # handle non-JSON payloads
                                if str_payload.casefold() == "on":
                                    logger.debug(
                                        f"{lp} setting power to ON (non-JSON) for: {node.id}{' [sub ID: {}]'.format(sub_id) if sub_id else ''}"
                                    ) if MQTT_DEBUG else None

                                    tasks.append(node.set_power(1, sub_id))
                                elif str_payload.casefold() == "off":
                                    logger.debug(
                                        f"{lp} setting power to OFF (non-JSON)"
                                    ) if MQTT_DEBUG else None
                                    tasks.append(node.set_power(0, sub_id))
                            else:
                                logger.warning(
                                    f"{lp} Unknown payload: {payload}, skipping..."
                                )
                else:
                    logger.warning(f"{lp} Unknown command: {topic} => {payload}")
                if tasks:
                    await asyncio.gather(*tasks)

            # messages sent to the hass mqtt topic
            elif _topic[0] == self.ha_topic:
                # birth / will
                if _topic[1] == CYNC_HASS_STATUS_TOPIC:
                    if payload.decode().casefold() == CYNC_HASS_BIRTH_MSG.casefold():
                        birth_delay = random.randint(5, 15)
                        logger.info(
                            f"{lp} HASS has sent MQTT BIRTH message, re-announcing device discovery, availability and status after a random delay of {birth_delay} seconds..."
                        )
                        # Give HASS some time to start up, from docs:
                        # To avoid high IO loads on the MQTT broker, adding some random delay in sending the discovery payload is recommended.
                        # this is a well known issue with HASS when they send the birth message. maybe its fixed, but this works
                        await asyncio.sleep(birth_delay)
                        # register devices
                        await self.homeassistant_discovery()
                        # give HASS a moment (to register devices)
                        await asyncio.sleep(2)
                        # set the device online/offline and set its status
                        for node in g.ncync_server.node_devices.values():
                            await self.pub_online(node.id, node.online)
                            for epoint_state in node.entities.values():
                                await self.parse_entity_state(
                                    epoint_state,
                                    from_pkt="'hass_birth'",
                                )

                    elif payload.decode().casefold() == CYNC_HASS_WILL_MSG.casefold():
                        logger.info(
                            f"{lp} received Last Will msg from Home Assistant, HASS is offline!"
                        )
                    else:
                        logger.warning(f"{lp} Unknown HASS status message: {payload}")

    async def stop(self):
        lp = f"{self.lp}stop:"
        # set all devices offline
        if self._connected:
            logger.debug(f"{lp} Setting all Cync devices offline...")
            for node in g.ncync_server.node_devices.values():
                node.online = False
            # ["state_topic"] = f"{self.topic}/status/bridge/mqtt_client/connected"
            await self.publish(
                f"{self.topic}/status/bridge/mqtt_client/connected",
                "OFF".encode(),
            )
            await self.publish(f"{self.topic}/availability/bridge", "offline".encode())
            await self.send_will_msg()
        try:
            logger.debug(f"{lp} Disconnecting from broker...")
            await self.client.__aexit__(None, None, None)
        except aiomqtt.MqttError as ce:
            logger.warning("%s MQTT disconnect failed: %s" % (lp, ce))
        except Exception as e:
            logger.warning("%s MQTT disconnect failed: %s" % (lp, e), exc_info=True)
        else:
            logger.info(f"{lp} Disconnected from MQTT broker")
        finally:
            self._connected = False
            if self.start_task and not self.start_task.done():
                logger.debug(f"{lp} FINISHING: Cancelling start task")
                self.start_task.cancel()

    async def pub_online(self, device_id: int, status: bool) -> bool:
        # no need for sub_id, if the parent device is online, children are online
        lp = f"{self.lp}pub_online:"
        if self._connected:
            if device_id not in g.ncync_server.node_devices:
                logger.error(
                    f"{lp} Device ID {device_id} not found?! Have you deleted or added any devices recently? "
                    f"You may need to re-export devices from your Cync account!"
                )
                return False
            availability = b"online" if status else b"offline"
            device: CyncDevice = g.ncync_server.node_devices[device_id]
            device_uuid = f"{device.home_id}-{device_id}"
            data = []
            if device.has_multi_endpoints:
                for child_id, child_name in device.entities.items():
                    data.append(
                        (
                            f"{self.topic}/availability/{device_uuid}-{child_id}",
                            availability,
                        )
                    )
            else:
                data.append((f"{self.topic}/availability/{device_uuid}", availability))
            # logger.debug(f"{lp} Publishing availability: {availability}")
            for _d in data:
                try:
                    _ = (
                        await self.client.publish(_d[0], _d[1], qos=0)
                        if not MQTT_DEAD
                        else None
                    )
                except aiomqtt.MqttError as mqtt_code_exc:
                    logger.warning(f"{lp} [MqttError] -> {mqtt_code_exc}")
                    self._connected = False
            return True
        return False

    async def update_endpoint_power(
        self, node: CyncDevice, state: int, sub_id: Optional[int] = None
    ) -> bool:
        """Update the device state and publish to MQTT for HASS devices to update."""
        node.online = True
        _id = sub_id if sub_id is not None else 0
        endpoint = node.entities.get(_id)
        endpoint.power = state
        power_status = "OFF" if state == 0 else "ON"
        mqtt_tgt_state = {"state": power_status}
        if node.is_plug or node.is_switch:
            mqtt_tgt_state = power_status.encode()  # send ON or OFF if plug
        else:
            mqtt_tgt_state = json.dumps(mqtt_tgt_state).encode()  # send JSON
        return await self.pub_endpoint_state(node, mqtt_tgt_state, sub_id)

    async def update_brightness(
        self, node: CyncDevice, bri: int, sub_id: Optional[int] = None
    ) -> bool:
        """Update the device brightness and publish to MQTT for HASS devices to update."""
        node.online = True
        _id = sub_id if sub_id is not None else 0
        endpoint = node.entities.get(_id)
        endpoint.brightness = bri
        state = "ON"
        if bri == 0:
            state = "OFF"
        mqtt_dev_state = {"state": state, "brightness": bri}
        return await self.pub_endpoint_state(
            node, json.dumps(mqtt_dev_state).encode(), sub_id
        )

    async def update_temperature(
        self, node: CyncDevice, temp: int, sub_id: Optional[int] = None
    ) -> bool:
        """Update the device temperature and publish to MQTT for HASS devices to update."""
        node.online = True
        _id = sub_id if sub_id is not None else 0
        endpoint = node.entities.get(_id)

        if node.supports_temperature:
            mqtt_dev_state = {
                "state": "ON",
                "color_mode": "color_temp",
                "color_temp": self.cync2kelvin(temp),
            }
            endpoint.temperature = temp
            endpoint.red = 0
            endpoint.green = 0
            endpoint.blue = 0
            return await self.pub_endpoint_state(
                node, json.dumps(mqtt_dev_state).encode(), sub_id
            )
        return False

    async def update_rgb(
        self, node: CyncDevice, rgb: tuple[int, int, int], sub_id: Optional[int] = None
    ) -> bool:
        """Update the device RGB and publish to MQTT for HASS devices to update. Intended for callbacks"""
        node.online = True
        _id = sub_id if sub_id is not None else 0
        endpoint = node.entities.get(_id)

        if node.supports_rgb and (
            any(
                [
                    rgb[0] is not None,
                    rgb[1] is not None,
                    rgb[2] is not None,
                ]
            )
        ):
            mqtt_tgt_state = {
                "state": "ON",
                "color_mode": "rgb",
                "color": {"r": rgb[0], "g": rgb[1], "b": rgb[2]},
            }
            endpoint.red = rgb[0]
            endpoint.green = rgb[1]
            endpoint.blue = rgb[2]
            endpoint.temperature = 254
            return await self.pub_endpoint_state(
                node, json.dumps(mqtt_tgt_state).encode(), sub_id
            )
        return False

    async def pub_endpoint_state(
        self,
        node: CyncDevice,
        msg: bytes,
        sub_id: Optional[int],
        from_pkt: Optional[str] = None,
    ) -> bool:

        lp = f"{self.lp}device_status:"
        if from_pkt:
            lp = f"{lp}{from_pkt}:"
        if self._connected:
            tgt_id = f"{node.hass_id}" if not sub_id else f"{node.hass_id}-{sub_id}"
            logger.debug(
                f"{lp} Sending {msg} for device: '{node.name}' (ID: {node.id}){" '{}' [sub ID: {}]".format(node.entities[sub_id].name, sub_id) if sub_id else ''}"
            ) if MQTT_DEBUG else None
            tpc = f"{self.topic}/status/{tgt_id}"
            try:
                await self.client.publish(
                    tpc,
                    msg,
                    qos=0,
                    timeout=3.0,
                ) if not MQTT_DEAD else None
            except aiomqtt.MqttError as mqtt_code_exc:
                logger.warning(f"{lp} [MqttError] -> {mqtt_code_exc}")
                self._connected = False
            except asyncio.CancelledError as can_exc:
                logger.debug(f"{lp} [Task Cancelled] -> {can_exc}")
            else:
                return True
        return False

    async def parse_entity_state(
        self,
        endpoint_state: EntityState,
        from_pkt: Optional[str] = None,
    ) -> bool:
        """Parse device status and publish to MQTT for HASS devices to update."""
        lp = f"{self.lp}parse state:"
        node_id = endpoint_state.dev_id
        sub_id = endpoint_state.sub_id
        if from_pkt:
            lp = f"{lp}{from_pkt}:"
        if node_id not in g.ncync_server.node_devices:
            logger.warning(
                f"{lp} Device ID {node_id} not found! Device may be disabled in config file or "
                f"you may need to re-export devices from your Cync account"
            )
            return False
        node: CyncDevice = g.ncync_server.node_devices[node_id]
        endpoint = node.entities[sub_id]
        power_status = "OFF" if endpoint.power == 0 else "ON"
        mqtt_dev_state: Union[Dict[str, Union[int, str, bytes, dict, list]], bytes] = {
            "state": power_status
        }

        if node.is_plug or node.is_switch:
            mqtt_dev_state = power_status.encode()

        else:
            if endpoint.brightness is not None:
                mqtt_dev_state["brightness"] = endpoint.brightness

            if endpoint.temperature is not None:
                if node.supports_rgb and (
                    any(
                        [
                            endpoint.red is not None,
                            endpoint.green is not None,
                            endpoint.blue is not None,
                        ]
                    )
                    and endpoint.temperature == 254
                ):
                    mqtt_dev_state["color_mode"] = "rgb"
                    mqtt_dev_state["color"] = {
                        "r": endpoint.red,
                        "g": endpoint.green,
                        "b": endpoint.blue,
                    }
                elif node.supports_temperature and (0 <= endpoint.temperature <= 100):
                    mqtt_dev_state["color_mode"] = "color_temp"
                    mqtt_dev_state["color_temp"] = self.cync2kelvin(
                        endpoint.temperature
                    )
            mqtt_dev_state = json.dumps(mqtt_dev_state).encode()

        return await self.pub_endpoint_state(
            node, mqtt_dev_state, sub_id, from_pkt=from_pkt
        )

    async def send_birth_msg(self) -> bool:
        lp = f"{self.lp}send_birth_msg:"
        if self._connected:
            logger.debug(
                f"{lp} Sending birth message ({CYNC_HASS_BIRTH_MSG}) to {self.topic}/status"
            )
            try:
                await self.client.publish(
                    f"{self.topic}/status",
                    CYNC_HASS_BIRTH_MSG.encode(),
                    qos=0,
                    retain=True,
                ) if not MQTT_DEAD else None
            except aiomqtt.MqttCodeError as mqtt_code_exc:
                logger.warning(
                    f"{lp} [MqttError] (rc: {mqtt_code_exc.rc}) -> {mqtt_code_exc}"
                )
            except asyncio.CancelledError as can_exc:
                logger.warning(f"{lp} [Task Cancelled] -> {can_exc}")
            else:
                return True
        return False

    async def send_will_msg(self) -> bool:
        lp = f"{self.lp}send_will_msg:"
        if self._connected:
            logger.debug(
                f"{lp} Sending will message ({CYNC_HASS_WILL_MSG}) to {self.topic}/status"
            )
            try:
                await self.client.publish(
                    f"{self.topic}/status",
                    CYNC_HASS_WILL_MSG.encode(),
                    qos=0,
                    retain=True,
                ) if not MQTT_DEAD else None
            except aiomqtt.MqttError as mqtt_code_exc:
                logger.warning(f"{lp} [MqttError] -> {mqtt_code_exc}")
                self._connected = False
            except Exception as e:
                logger.warning(f"{lp} [Exception] -> {e}")
            else:
                return True
        return False

    async def _publish_entity(
        self, device: CyncDevice, registry_struct: dict, entity_uuid: str
    ):
        tpc_str_template = "{0}/{1}/{2}/config"
        dev_type = "light"
        if device.is_light:
            pass
        elif device.is_switch:
            dev_type = "switch"
            if device.metadata.capabilities.fan:
                dev_type = "fan"
        if dev_type == "light":
            registry_struct["supported_color_modes"] = []
            registry_struct.update({"brightness_scale": 100})
            if device.supports_temperature or device.supports_rgb:
                if device.supports_temperature:
                    registry_struct["supported_color_modes"].append("color_temp")
                    registry_struct["color_temp_kelvin"] = True
                    min_k = CYNC_MINK
                    max_k = CYNC_MAXK
                    if device.metadata.characteristics:
                        min_k = device.metadata.characteristics.min_kelvin if device.metadata.characteristics.min_kelvin is not None else CYNC_MINK
                        max_k = device.metadata.characteristics.max_kelvin if device.metadata.characteristics.max_kelvin is not None else CYNC_MAXK
                    registry_struct["min_kelvin"] = min_k
                    registry_struct["max_kelvin"] = max_k
                if device.supports_rgb:
                    registry_struct["supported_color_modes"].append("rgb")
                    registry_struct["effect"] = True
                    registry_struct["effect_list"] = list(FACTORY_EFFECTS_BYTES.keys())
                if device.metadata.capabilities.dynamic:
                    pass
                # add brightness : True only when supported_color_modes are present
                registry_struct.update({"brightness": True})
            if not registry_struct["supported_color_modes"]:
                registry_struct["supported_color_modes"].append("brightness")

        elif dev_type == "fan":
            registry_struct["platform"] = "fan"
            # fan can be controlled via light control structs: brightness -> max=100, high=75, medium=50, low=25, off=0
            registry_struct["percentage_command_topic"] = (
                "{0}/set/{1}/percentage".format(self.topic, entity_uuid)
            )
            registry_struct["percentage_state_topic"] = (
                "{0}/status/{1}/percentage".format(self.topic, entity_uuid)
            )
            registry_struct["preset_modes"] = [
                "off",
                "low",
                "medium",
                "high",
                "max",
            ]
            registry_struct["preset_mode_command_topic"] = "{0}/set/{1}/preset".format(
                self.topic, entity_uuid
            )
            registry_struct["preset_mode_state_topic"] = "{0}/status/{1}/preset".format(
                self.topic, entity_uuid
            )

        tpc = tpc_str_template.format(self.ha_topic, dev_type, entity_uuid)
        try:
            _ = (
                await self.client.publish(
                    tpc,
                    json.dumps(registry_struct).encode(),
                    qos=0,
                    retain=False,
                )
                if not MQTT_DEAD
                else None
            )

        except Exception as e:
            logger.error(
                "%s - Unable to publish mqtt message... skipped -> %s" % (lp, e)
            )

    def _get_device_registry(self, node: CyncDevice):
        device_uuid = node.hass_id
        unique_id = f"{node.home_id}_{node.id}"
        obj_id = f"cync_lan_{unique_id}"
        dev_fw_version = str(node.version)
        ver_str = "Unknown"
        fw_len = len(dev_fw_version)
        if fw_len == 5:
            if dev_fw_version != 00000:
                ver_str = (
                    f"{dev_fw_version[0]}.{dev_fw_version[1]}.{dev_fw_version[2:]}"
                )
        elif fw_len == 2:
            ver_str = f"{dev_fw_version[0]}.{dev_fw_version[1]}"
        model_str = "Unknown"
        if node.type in device_type_map:
            model_str = device_type_map[node.type].model_string
        dev_connections = [("bluetooth", node.mac.casefold())]
        if not node.bt_only:
            dev_connections.append(("mac", node.wifi_mac.casefold()))
        device_registry_struct = {
            "identifiers": [unique_id],
            "manufacturer": CYNC_MANUFACTURER,
            "connections": dev_connections,
            "name": node.name,
            "sw_version": ver_str,
            "model": model_str,
            "via_device": str(g.uuid),
        }

        return device_registry_struct

    async def homeassistant_discovery(self) -> bool:
        """Build each configured Cync device for HASS device registry"""
        lp = f"{self.lp}hass:"
        ret = False
        if self._connected:
            logger.info(f"{lp} Starting device discovery...")
            await self.create_bridge_device()
            try:
                for node_repr in g.ncync_server.node_devices.values():
                    device_uuid = node_repr.hass_id
                    if node_repr.metadata is None:
                        logger.warning(
                            f"{lp} Device '{node_repr.name}' (ID: {node_repr.id} / Type: {node_repr.type}) has no metadata,"
                            f" meaning this type hasn't been seen before and can not be controlled, please "
                            f"see: https://github.com/baudneo/cync-lan/issues/12 to have this device added"
                        )
                        continue
                    supported = node_repr.metadata.supported
                    if not supported:
                        logger.warning(
                            f"{lp} Device '{node_repr.name}' (ID: {node_repr.id} / Type: {node_repr.type}) is not supported, skipping HASS discovery..."
                        )
                        continue

                    unique_id = f"{node_repr.home_id}_{node_repr.id}"
                    obj_id = f"cync_lan_{unique_id}"
                    dev_fw_version = str(node_repr.version)
                    ver_str = "Unknown"
                    fw_len = len(dev_fw_version)
                    if fw_len == 5:
                        if dev_fw_version != 00000:
                            ver_str = f"{dev_fw_version[0]}.{dev_fw_version[1]}.{dev_fw_version[2:]}"
                    elif fw_len == 2:
                        ver_str = f"{dev_fw_version[0]}.{dev_fw_version[1]}"
                    model_str = "Unknown"
                    if node_repr.type in device_type_map:
                        model_str = device_type_map[node_repr.type].model_string
                    dev_connections = [("bluetooth", node_repr.mac.casefold())]
                    if not node_repr.bt_only:
                        dev_connections.append(("mac", node_repr.wifi_mac.casefold()))
                    device_registry_struct = {
                        "identifiers": [unique_id],
                        "manufacturer": CYNC_MANUFACTURER,
                        "connections": dev_connections,
                        "name": node_repr.name,
                        "sw_version": ver_str,
                        "model": model_str,
                        "via_device": str(g.uuid),
                    }
                    entity_registry_struct = {
                        # retain for older HASS versions
                        "object_id": obj_id,
                        "default_entity_id": obj_id,
                        # set to None if only device name is relevant, this sets entity name
                        "name": None,
                        "command_topic": "{0}/set/{1}".format(self.topic, device_uuid),
                        "state_topic": "{0}/status/{1}".format(self.topic, device_uuid),
                        "avty_t": "{0}/availability/{1}".format(
                            self.topic, device_uuid
                        ),
                        "pl_avail": "online",
                        "pl_not_avail": "offline",
                        "state_on": "ON",
                        "state_off": "OFF",
                        "unique_id": unique_id,
                        "schema": "json",
                        "origin": ORIGIN_STRUCT,
                        "device": device_registry_struct,
                        "optimistic": False,
                    }

                    if node_repr.has_multi_endpoints:
                        logger.debug(
                            f"{lp} Device '{node_repr.name}' (ID: {node_repr.id}) has {len(node_repr.entities)} endpoints, creating "
                            f"separate HASS entities for each endpoint..."
                        )
                        for ep_id, ep_state in node_repr.entities.items():
                            cobj_id = f"cync_lan_{unique_id}_{ep_id}"
                            cdevice_uuid = (
                                f"{node_repr.hass_id}-{ep_id}"  # home_id-device_id-ep_id
                            )
                            entity_registry_struct["command_topic"] = (
                                "{0}/set/{1}".format(self.topic, cdevice_uuid)
                            )
                            entity_registry_struct["state_topic"] = (
                                "{0}/status/{1}".format(self.topic, cdevice_uuid)
                            )
                            entity_registry_struct["avty_t"] = (
                                "{0}/availability/{1}".format(self.topic, cdevice_uuid)
                            )
                            entity_registry_struct["object_id"] = cobj_id
                            entity_registry_struct["default_entity_id"] = cobj_id
                            entity_registry_struct["name"] = ep_state.name
                            entity_registry_struct["unique_id"] = (
                                f"{node_repr.home_id}_{node_repr.id}_{ep_id}"
                            )
                            await self._publish_entity(
                                node_repr, entity_registry_struct, cdevice_uuid
                            )
                    else:
                        # single entity for a single device with no children
                        await self._publish_entity(
                            node_repr, entity_registry_struct, device_uuid
                        )
                    if node_repr.metadata and node_repr.metadata.type == DeviceClassification.LIGHT and node_repr.metadata.capabilities.dynamic:
                        # todo: segmented lights; can be controlled as a whole and/or per segment?
                        #  are segment lights only branded as 'dynamic', what about a music effects button?
                        logger.debug(f"{lp} This device has been identified as a 'dynamic' light...")
                        pass


            except aiomqtt.MqttCodeError as mqtt_code_exc:
                logger.warning(
                    f"{lp} [MqttError] (rc: {mqtt_code_exc.rc}) -> {mqtt_code_exc}"
                )
                self._connected = False
            except asyncio.CancelledError as can_exc:
                logger.warning(f"{lp} [Task Cancelled] -> {can_exc}")
                raise can_exc
            except Exception as e:
                logger.exception(f"{lp} [Exception] -> {e}")
            else:
                ret = True
        logger.debug(f"{lp} Discovery complete (success: {ret})")
        return ret

    async def add_mitm_button(self, node: CyncDevice):
        """Add a MITM Mode button dynamically. Send empty message to the hass config topic to delete the entity."""
        logger.debug(
            f"{node.lp} Adding a 'MITM mode' button to node: '{node.name}' (ID: {node.id}) as it is "
            f"connected via IP: {node.tcp_session.ip_address}"
        )
        device_uuid = node.hass_id
        mitm_switch_unique_id = f"{node.home_id}_{node.id}_mitm_mode"
        mitm_switch_conf = {
            "name": f"{node.name} MITM Mode",
            "unique_id": mitm_switch_unique_id,
            "command_topic": f"{self.topic}/set/{device_uuid}/mitm",
            "state_topic": f"{self.topic}/status/{device_uuid}/mitm",
            "icon": "mdi:incognito",
            "device": self._get_device_registry(node),
            "platform": "switch",
        }
        await self.publish_json_msg(
            f"{self.ha_topic}/switch/{mitm_switch_unique_id}/config", mitm_switch_conf
        )
        seeded = await self.publish(f"{self.topic}/status/{device_uuid}/mitm", b"OFF", retain=True)

    async def remove_mitm_button(self, node: CyncDevice):
        """Delete a MITM mode button"""
        logger.debug(f"{node.lp} Removing 'MITM mode' button from node: '{node.name}'")
        mitm_switch_unique_id = f"{node.home_id}_{node.id}_mitm_mode"
        await self.publish(f"{self.topic}/status/{device_uuid}/mitm", b"OFF", retain=True)
        # send empty payload to the config topic to delete the entity
        await self.publish(
            f"{self.ha_topic}/switch/{mitm_switch_unique_id}/config", b""
        )

    async def create_bridge_device(self) -> bool:
        """Create the device / entity registry config for the CyncLAN bridge itself."""
        global bridge_device_reg_struct
        # want to expose buttons (restart, start export, submit otp)
        # want to expose some sensors that show the number of devices, number of online devices, etc.
        # sensors to show if MQTT is connected, if the CyncLAN server is running, etc.
        # input_number to submit OTP for export
        lp = f"{self.lp}create_bridge_device:"
        ret = False

        logger.debug(f"{lp} Creating CyncLAN bridge device...")
        bridge_base_unique_id = "cync_lan_bridge"
        ver_str = CYNC_VERSION
        pub_tasks: List[asyncio.Task] = []
        # Bridge device config
        bridge_device_reg_struct = {
            "identifiers": [str(g.uuid)],
            # add 'Savant' so it shows when filtering by 'Savant' in mqtt device list
            "manufacturer": "baudneo [not Savant]",
            "name": "CyncLAN Bridge",
            "sw_version": ver_str,
            "model": "Local Push Controller",
        }
        # Entities for the bridge device
        entity_type = "button"
        template_tpc = "{0}/{1}/{2}/config"
        pub_tasks.append(
            self.publish(f"{self.topic}/availability/bridge", "online".encode())
        )

        entity_unique_id = f"{bridge_base_unique_id}_restart"
        restart_btn_entity_struct = {
            "platform": "button",
            # obj_id is to link back to the bridge device
            "object_id": CYNC_BRIDGE_OBJ_ID + "_restart",
            "default_entity_id": CYNC_BRIDGE_OBJ_ID + "_restart",
            "command_topic": f"{self.topic}/set/bridge/restart",
            "state_topic": f"{self.topic}/status/bridge/restart",
            "avty_t": f"{self.topic}/availability/bridge",
            "name": "Restart CyncLAN Bridge",
            "unique_id": entity_unique_id,
            "schema": "json",
            "origin": ORIGIN_STRUCT,
            "device": bridge_device_reg_struct,
        }
        ret = await self.publish_json_msg(
            template_tpc.format(self.ha_topic, entity_type, entity_unique_id),
            restart_btn_entity_struct,
        )
        if ret is False:
            logger.error(f"{lp} Failed to publish restart button entity config")

        entity_unique_id = f"{bridge_base_unique_id}_start_export"
        xport_btn_entity_conf = restart_btn_entity_struct.copy()
        xport_btn_entity_conf["default_entity_id"] = entity_unique_id
        xport_btn_entity_conf["command_topic"] = f"{self.topic}/set/bridge/export/start"
        xport_btn_entity_conf["state_topic"] = (
            f"{self.topic}/status/bridge/export/start"
        )
        xport_btn_entity_conf["name"] = "Start Export"
        xport_btn_entity_conf["unique_id"] = entity_unique_id
        ret = await self.publish_json_msg(
            template_tpc.format(self.ha_topic, entity_type, entity_unique_id),
            xport_btn_entity_conf,
        )
        if ret is False:
            logger.error(f"{lp} Failed to publish start export button entity config")

        entity_unique_id = f"{bridge_base_unique_id}_submit_otp"
        submit_otp_btn_entity_conf = restart_btn_entity_struct.copy()
        submit_otp_btn_entity_conf["default_entity_id"] = (
            CYNC_BRIDGE_OBJ_ID + "_submit_otp"
        )
        submit_otp_btn_entity_conf["command_topic"] = (
            f"{self.topic}/set/bridge/otp/submit"
        )
        submit_otp_btn_entity_conf["state_topic"] = (
            f"{self.topic}/status/bridge/otp/submit"
        )
        submit_otp_btn_entity_conf["name"] = "Submit OTP"
        submit_otp_btn_entity_conf["unique_id"] = entity_unique_id
        ret = await self.publish_json_msg(
            template_tpc.format(self.ha_topic, entity_type, entity_unique_id),
            submit_otp_btn_entity_conf,
        )
        if ret is False:
            logger.error(f"{lp} Failed to publish submit OTP button entity config")

        # binary sensor for if the TCP server is running
        # binary sensor for if the export server is running
        # binary sensor for if the MQTT client is connected
        entity_type = "binary_sensor"
        entity_unique_id = f"{bridge_base_unique_id}_tcp_server_running"
        tcp_server_entity_conf = {
            "object_id": entity_unique_id,
            "default_entity_id": entity_unique_id,
            "name": "nCync TCP Server Running",
            "state_topic": f"{self.topic}/status/bridge/tcp_server/running",
            "unique_id": entity_unique_id,
            "device_class": "running",
            "icon": "mdi:server-network",
            "avty_t": f"{self.topic}/availability/bridge",
            "schema": "json",
            "origin": ORIGIN_STRUCT,
            "device": bridge_device_reg_struct,
        }
        ret = await self.publish_json_msg(
            template_tpc.format(self.ha_topic, entity_type, entity_unique_id),
            tcp_server_entity_conf,
        )
        if ret is False:
            logger.error(f"{lp} Failed to publish TCP server running entity config")
        status = "ON" if g.ncync_server.running is True else "OFF"
        pub_tasks.append(
            self.publish(
                f"{self.topic}/status/bridge/tcp_server/running", status.encode()
            )
        )

        entity_unique_id = f"{bridge_base_unique_id}_export_server_running"
        export_server_entity_conf = tcp_server_entity_conf.copy()
        export_server_entity_conf["default_entity_id"] = entity_unique_id
        export_server_entity_conf["name"] = "Cync Export Server Running"
        export_server_entity_conf["state_topic"] = (
            f"{self.topic}/status/bridge/export_server/running"
        )
        export_server_entity_conf["unique_id"] = entity_unique_id
        export_server_entity_conf["icon"] = "mdi:export-variant"
        ret = await self.publish_json_msg(
            template_tpc.format(self.ha_topic, entity_type, entity_unique_id),
            export_server_entity_conf,
        )
        if ret is False:
            logger.error(f"{lp} Failed to publish export server running entity config")
        status = (
            "ON" if (g.export_server and g.export_server.running is True) else "OFF"
        )
        pub_tasks.append(
            self.publish(
                f"{self.topic}/status/bridge/export_server/running", status.encode()
            )
        )

        entity_unique_id = f"{bridge_base_unique_id}_mqtt_client_connected"
        mqtt_client_entity_conf = tcp_server_entity_conf.copy()
        mqtt_client_entity_conf["default_entity_id"] = entity_unique_id
        mqtt_client_entity_conf["name"] = "Cync MQTT Client Connected"
        mqtt_client_entity_conf["state_topic"] = (
            f"{self.topic}/status/bridge/mqtt_client/connected"
        )
        mqtt_client_entity_conf["unique_id"] = entity_unique_id
        mqtt_client_entity_conf["icon"] = "mdi:connection"
        mqtt_client_entity_conf["device_class"] = "connectivity"
        ret = await self.publish_json_msg(
            template_tpc.format(self.ha_topic, entity_type, entity_unique_id),
            mqtt_client_entity_conf,
        )
        if ret is False:
            logger.error(f"{lp} Failed to publish MQTT client connected entity config")

        # input number for OTP input
        entity_type = "number"
        entity_unique_id = f"{bridge_base_unique_id}_otp_input"
        otp_num_entity_cfg = {
            "platform": "number",
            "object_id": entity_unique_id,
            "default_entity_id": entity_unique_id,
            "icon": "mdi:lock",
            "command_topic": f"{self.topic}/set/bridge/otp/input",
            "state_topic": f"{self.topic}/status/bridge/otp/input",
            "avty_t": f"{self.topic}/availability/bridge",
            "schema": "json",
            "origin": ORIGIN_STRUCT,
            "device": bridge_device_reg_struct,
            "min": 000000,
            "max": 999999,
            "mode": "box",
            "name": "Cync emailed OTP",
            "unique_id": entity_unique_id,
        }
        ret = await self.publish_json_msg(
            template_tpc.format(self.ha_topic, entity_type, entity_unique_id),
            otp_num_entity_cfg,
        )
        if ret is False:
            logger.error(f"{lp} Failed to publish OTP input number entity config")

        # Sensors
        entity_type = "sensor"
        entity_unique_id = f"{bridge_base_unique_id}_connected_tcp_devices"
        num_tcp_devices_entity_conf = {
            "platform": "sensor",
            "object_id": entity_unique_id,
            "default_entity_id": entity_unique_id,
            "name": "TCP Devices Connected",
            "state_topic": f"{self.topic}/status/bridge/tcp_devices/connected",
            "unique_id": entity_unique_id,
            "icon": "mdi:counter",
            "avty_t": f"{self.topic}/availability/bridge",
            # "unit_of_measurement": "TCP device(s)",
            "schema": "json",
            "origin": ORIGIN_STRUCT,
            "device": bridge_device_reg_struct,
        }
        ret = await self.publish_json_msg(
            template_tpc.format(self.ha_topic, entity_type, entity_unique_id),
            num_tcp_devices_entity_conf,
        )
        if ret is False:
            logger.warning(
                f"{lp} Failed to publish number of TCP devices connected entity config"
            )
        pub_tasks.append(
            self.publish(
                f"{self.topic}/status/bridge/tcp_devices/connected",
                str(len(g.ncync_server.tcp_connections)).encode(),
            )
        )
        # total cync devices managed
        total_cync_devs = len(g.ncync_server.node_devices)
        entity_unique_id = f"{bridge_base_unique_id}_total_cync_devices"
        total_cync_devs_entity_conf = num_tcp_devices_entity_conf.copy()
        total_cync_devs_entity_conf["default_entity_id"] = entity_unique_id
        total_cync_devs_entity_conf["name"] = "Cync Devices Managed"
        total_cync_devs_entity_conf["state_topic"] = (
            f"{self.topic}/status/bridge/cync_devices/total"
        )
        total_cync_devs_entity_conf["unique_id"] = entity_unique_id
        # total_cync_devs_entity_conf["unit_of_measurement"] = "Cync device(s)"
        ret = await self.publish_json_msg(
            template_tpc.format(self.ha_topic, entity_type, entity_unique_id),
            total_cync_devs_entity_conf,
        )
        if ret is False:
            logger.warning(
                f"{lp} Failed to publish total Cync devices managed entity config"
            )
        pub_tasks.append(
            self.publish(
                f"{self.topic}/status/bridge/cync_devices/total",
                str(total_cync_devs).encode(),
            )
        )

        # Should restart sensor, to be used to restart the app/container
        entity_type = "binary_sensor"
        entity_unique_id = f"{bridge_base_unique_id}_should_restart"
        restart_sensor_entity_conf = {
            "platform": "sensor",
            "object_id": entity_unique_id,
            "default_entity_id": entity_unique_id,
            "name": "Should Restart",
            "state_topic": f"{self.topic}/status/bridge/should_restart",
            "unique_id": entity_unique_id,
            "icon": "mdi:restart",
            "avty_t": f"{self.topic}/availability/bridge",
            "device_class": "problem",
            "schema": "json",
            "origin": ORIGIN_STRUCT,
            "device": bridge_device_reg_struct,
        }
        ret = await self.publish_json_msg(
            template_tpc.format(self.ha_topic, entity_type, entity_unique_id),
            restart_sensor_entity_conf,
        )
        if ret is False:
            logger.warning(f"{lp} Failed to publish should restart entity config")
        pub_tasks.append(
            self.publish(
                f"{self.topic}/status/bridge/should_restart",
                "OFF".encode(),
            )
        )

        # App Connections Sensor
        app_count_unique_id = "cync_lan_bridge_app_count"
        app_count_conf = {
            "name": "Connected Cync Apps",
            "unique_id": app_count_unique_id,
            "state_topic": f"{self.topic}/status/bridge/apps/connected",
            "icon": "mdi:cellphone-cog",
            "device": bridge_device_reg_struct,
            "platform": "sensor",
        }
        await self.publish_json_msg(
            f"{self.ha_topic}/sensor/{app_count_unique_id}/config", app_count_conf
        )

        # app_logging_unique_id = "cync_lan_bridge_app_logging"
        # app_logging_conf = {
        #     "name": "Global App MITM Logging",
        #     "unique_id": app_logging_unique_id,
        #     "command_topic": f"{self.topic}/set/bridge/app_logging",
        #     "state_topic": f"{self.topic}/status/bridge/app_logging",
        #     "icon": "mdi:file-find",
        #     "device": bridge_device_reg_struct,
        #     "platform": "switch",
        # }
        # await self.publish_json_msg(
        #     f"{self.ha_topic}/switch/{app_logging_unique_id}/config", app_logging_conf
        # )

        await asyncio.gather(*pub_tasks, return_exceptions=True)
        logger.debug(f"{lp} Bridge device config published and seeded")
        return ret

    async def publish(self, topic: str, msg_data: bytes, retain: bool = None, qos: int = None):
        """Publish a message to the MQTT broker."""
        lp = f"{self.lp}publish:"
        if not self._connected:
            return False
        if retain is None:
            retain = False
        if qos is None:
            qos = 0
        try:
            if not MQTT_DEAD:
                _ = await self.client.publish(topic, msg_data, qos=qos, retain=retain)
            else:
                logger.debug(
                    f"{lp} CYNC_MQTT_DEAD has been turned on, not publishing the message, change the env var if you want to sub/pub"
                )
        except aiomqtt.MqttError as mqtt_code_exc:
            logger.warning(
                f"{lp} [MqttError] (rc: {mqtt_code_exc.rc}) -> {mqtt_code_exc}"
            )
            self._connected = False
        except asyncio.CancelledError as can_exc:
            logger.warning(f"{lp} [Task Cancelled] -> {can_exc}")
        except Exception as e:
            logger.warning(f"{lp} [Exception] -> {e}")
        else:
            return True
        return False

    async def publish_json_msg(self, topic: str, msg_data: dict, retain: bool = None, qos: int = None) -> bool:
        lp = f"{self.lp}publish_msg:"
        if retain is None:
            retain = False
        if qos is None:
            qos = 0
        try:
            _ = (
                await self.client.publish(
                    topic, json.dumps(msg_data).encode(), qos=qos, retain=retain
                )
                if not MQTT_DEAD
                else None
            )
        except aiomqtt.MqttError as mqtt_code_exc:
            logger.warning(
                f"{lp} [MqttError] (rc: {mqtt_code_exc.rc}) -> {mqtt_code_exc}"
            )
        except asyncio.CancelledError as can_exc:
            logger.warning(f"{lp} [Task Cancelled] -> {can_exc}")
        except Exception as e:
            logger.warning(f"{lp} [Exception] -> {e}")
        else:
            return True
        return False

    def kelvin2cync(self, k):
        """Convert Kelvin value to Cync white temp (0-100) with step size: 1"""
        max_k = CYNC_MAXK
        min_k = CYNC_MINK
        if k < min_k:
            return 0
        elif k > max_k:
            return 100
        scale = 100 / (max_k - min_k)
        ret = int(scale * (k - min_k))
        # logger.debug(f"{self.lp} Converting Kelvin: {k} using scale: {scale} (max_k={max_k}, min_k={min_k}) -> return value: {ret}")
        return ret

    def cync2kelvin(self, ct):
        """Convert Cync white temp (0-100) to Kelvin value"""
        max_k = CYNC_MAXK
        min_k = CYNC_MINK
        if ct <= 0:
            return min_k
        elif ct >= 100:
            return max_k
        scale = (max_k - min_k) / 100
        ret = min_k + int(scale * ct)
        # logger.debug(f"{self.lp} Converting Cync temp: {ct} using scale: {scale} (max_k={max_k}, min_k={min_k}) -> return value: {ret}")
        return ret
