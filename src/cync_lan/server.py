import asyncio
import logging
import ssl
from typing import Dict, List, Mapping, Optional, Set, Union

import uvloop

from cync_lan.const import (
    CYNC_HOME_NO_BRIDGE_GRACE_EXPLICIT,
    CYNC_HOME_NO_BRIDGE_GRACE_SECS,
    CYNC_LOG_NAME,
    CYNC_SRV_HOST,
    CYNC_SRV_PORT,
)
from cync_lan.devices import CyncTCPSession
from cync_lan.devices.registry import DeviceRegistry
from cync_lan.stats import stats
from cync_lan.structs import GlobalObject

__all__ = [
    "nCyncServer",
]
logger = logging.getLogger(CYNC_LOG_NAME)
g = GlobalObject()


class nCyncServer:
    """
    A class to represent a Cync LAN server that listens for connections from Cync Wi-Fi devices.
    The Wi-Fi devices translate messages, status updates and commands to/from the Cync BTLE mesh.
    """

    node_devices: DeviceRegistry
    tcp_connections: Dict[str, Optional[CyncTCPSession]]
    app_tcp_connections: Dict[str, Optional[CyncTCPSession]]
    shutting_down: bool = False
    running: bool = False
    host: str
    port: int
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    loop: Union[asyncio.AbstractEventLoop, uvloop.Loop]
    _server: Optional[asyncio.Server] = None
    lp: str = "nCync:"
    start_task: Optional[asyncio.Task] = None
    _instance: Optional["nCyncServer"] = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @staticmethod
    def _is_bridge(d: CyncTCPSession) -> bool:
        # a session counts once can_connect() admitted it; until then (and while a rejected one sleeps in
        # blackhole()) it is not a bridge: it must not take a max_clients slot, a stale-vote seat or a command
        return not d.is_closed() and not d.is_app and d.allowed_to_connect

    def get_dev_tcp_pool_sync(self, home_id: Optional[int] = None) -> List[CyncTCPSession]:
        """
        Admitted, live bridges. With ``home_id``: only the bridges whose session home was resolved to that home (a
        bridge relays only its own home's mesh; a session whose home is not known yet is in no home's pool, so it
        never gets a command). Without it: every bridge (connection limits, counters).
        """
        return [
            d for d in self.tcp_connections.values()
            if self._is_bridge(d) and (home_id is None or getattr(d, "home_id", None) == home_id)
        ]

    async def get_dev_tcp_pool(self, home_id: Optional[int] = None) -> List[CyncTCPSession]:
        return self.get_dev_tcp_pool_sync(home_id)

    async def revote_offline(self) -> int:
        """Re-run every device's stale vote against its own home's TCP pool (called when a device session closes)."""
        if g.mqtt_client is None:
            return 0
        live_ips: Dict[Optional[int], List[str]] = {}
        marked = 0
        for dev in self.node_devices.values():
            if dev.home_id not in live_ips:
                live_ips[dev.home_id] = [d.ip_address for d in self.get_dev_tcp_pool_sync(dev.home_id)]
            marked += dev.revote_stale(live_ips[dev.home_id])
        return marked

    # ---- per-home "no bridge" grace (multi-home, see docs/multi_home.md)
    def start_home_grace(self, home_id: int) -> Optional[asyncio.Task]:
        """
        Arm the no-bridge timer for a home (at start, and when the home's last bridge closed). On expiry, if the home
        still has no bridge, a WARNING names it and its devices are marked offline. Already armed: left alone.
        With one home it only runs when the user set CYNC_HOME_NO_BRIDGE_GRACE_SECS (single-home installs keep their
        old behaviour: no offline marking just because the bridge is away for a moment).
        """
        if self.home_grace_secs <= 0 or self.shutting_down:
            return None
        if len(self.node_devices.home_ids()) < 2 and not self.home_grace_explicit:
            return None
        task = self.home_grace_tasks.get(home_id)
        if task is not None and not task.done():
            return task
        task = asyncio.create_task(
            self._home_no_bridge_grace(home_id, self.home_grace_secs), name=f"home_no_bridge_grace-{home_id}"
        )
        self.home_grace_tasks[home_id] = task
        return task

    def cancel_home_grace(self, home_id: Optional[int]) -> bool:
        """A bridge is up in this home: disarm its no-bridge timer. The task stays referenced until it finished."""
        # the next time this home has no bridge is a new outage: its first dropped command warns again
        self._drop_warned_homes.discard(home_id)
        task = self.home_grace_tasks.get(home_id)
        if task is None or task.done():
            return False
        task.cancel()
        return True

    def first_drop_in_outage(self, home_id: Optional[int]) -> bool:
        """
        A command for this home was dropped because it has no bridge. True for the first drop since the home last had a
        bridge (log it as a WARNING), False for the repeats (a dimmer slider or an automation would flood the log).
        """
        if home_id in self._drop_warned_homes:
            return False
        self._drop_warned_homes.add(home_id)
        return True

    async def _home_no_bridge_grace(self, home_id: int, delay: float):
        lp = f"{self.lp}home_grace:"
        try:
            await asyncio.sleep(delay)
        except asyncio.CancelledError:
            logger.debug(f"{lp} home {self.node_devices.describe_home(home_id)} has a bridge again, timer cancelled")
            raise
        if self.get_dev_tcp_pool_sync(home_id):
            # a bridge resolved into the home and nothing cancelled us (race): nothing to report
            return
        devices = self.node_devices.in_home(home_id)
        logger.warning(
            f"{lp} No TCP bridge for Cync home {self.node_devices.describe_home(home_id)} after {delay:g} seconds: "
            f"its {len(devices)} device(s) are marked offline and commands to them are dropped until one of its "
            f"Wi-Fi devices connects. Check that this home's devices are DNS-redirected to this server; if a bridge "
            f"is connected but its home could not be worked out, there is a WARNING about it (see docs/multi_home.md)."
        )
        for dev in devices:
            dev.online = False

    async def bridge_closed(self, session: CyncTCPSession) -> None:
        """A device session closed: arm the grace timer if it was the last bridge of its home."""
        home_id = getattr(session, "home_id", None)
        if home_id is None or session.is_app:
            return
        if not self.get_dev_tcp_pool_sync(home_id):
            self.start_home_grace(home_id)

    async def _stop_home_grace(self):
        tasks = [t for t in self.home_grace_tasks.values() if not t.done()]
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.wait(tasks)
        self.home_grace_tasks.clear()

    def __init__(
        self,
        node_map: Mapping,
        home_grace_secs: float = CYNC_HOME_NO_BRIDGE_GRACE_SECS,
        home_grace_explicit: bool = CYNC_HOME_NO_BRIDGE_GRACE_EXPLICIT,
    ):
        if not isinstance(node_map, DeviceRegistry):
            # a plain {id: device} mapping (older callers): every device must carry its home_id
            registry = DeviceRegistry()
            for dev in node_map.values():
                registry.add(dev)
            node_map = registry
        self.node_devices: DeviceRegistry = node_map
        self.home_grace_secs: float = home_grace_secs
        self.home_grace_explicit: bool = home_grace_explicit
        self.home_grace_tasks: Dict[int, asyncio.Task] = {}
        # homes whose "command dropped, no bridge" WARNING was already logged in the current outage
        self._drop_warned_homes: Set[Optional[int]] = set()
        self.tcp_connections = {}
        self.app_tcp_connections = {}
        self.tcp_conn_attempts: dict = {}
        self.ssl_context: Optional[ssl.SSLContext] = None
        self.host: str = CYNC_SRV_HOST
        self.port: str = CYNC_SRV_PORT
        g.reload_env()
        self.cert_file = g.env.cync_srv_ssl_cert
        self.key_file = g.env.cync_srv_ssl_key
        self.loop: Union[asyncio.AbstractEventLoop, uvloop.Loop] = (
            asyncio.get_event_loop()
        )

    async def remove_tcp_device(
        self, device: Union[CyncTCPSession, str]
    ) -> Optional[CyncTCPSession]:
        """
        Remove a TCP device from the server's device list.
        :param device: The CyncTCPDevice to remove.
        """
        dev = None
        lp = f"{self.lp}remove_tcp_device:"
        if isinstance(device, str):
            # if device is a string, it is the address
            if device in self.tcp_connections:
                device = self.tcp_connections[device]

        if isinstance(device, CyncTCPSession):
            if device.ip_address in self.tcp_connections:
                dev = self.tcp_connections.pop(device.ip_address, None)
                if dev is not None:
                    logger.debug(
                        f"{lp} Removed TCP device {device.ip_address} from server.tcp_devices."
                    )
                    # "state_topic": f"{self.topic}/status/bridge/tcp_devices/connected",
                    if g.mqtt_client is not None:
                        await g.mqtt_client.publish(
                            f"{g.env.mqtt_topic}/status/bridge/tcp_devices/connected",
                            str(len(self.tcp_connections)).encode(),
                        )
            else:
                logger.warning(
                    f"{lp} Device {device.ip_address} not found in TCP devices."
                )
        await self._update_app_stats()
        return dev

    async def add_tcp_device(self, device: CyncTCPSession):
        """
        Add a TCP device to the server's device list.
        :param device: The CyncTCPDevice to add.
        """
        lp = f"{self.lp}add_tcp_conn:"
        self.tcp_connections[device.ip_address] = device
        logger.debug(f"{lp} Adding {device.ip_address}")
        await self._update_app_stats()
        await device.start_tasks()

    async def _update_app_stats(self):
        """Publish count and IPs of connected apps."""
        if not g.mqtt_client:
            return
        apps = self.app_tcp_connections.values()
        # app_ips = [d.ip_address for d in apps]
        # todo: add app ip addresses as an attribute
        await g.mqtt_client.publish(
            f"{g.env.mqtt_topic}/status/bridge/apps/connected", str(len(apps)).encode()
        )

        devs = self.get_dev_tcp_pool_sync()
        await g.mqtt_client.publish(
            f"{g.env.mqtt_topic}/status/bridge/tcp_devices/connected",
            str(len(devs)).encode(),
        )


    async def create_ssl_context(self):
        # Allow the server to use a self-signed certificate
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
        # turn off all the SSL verification
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        # figured out from debugging using socat
        # AES256-SHA256 to cloud
        # devices: ECDHE-RSA-AES256-GCM-SHA384
        # tls 1.2
        ciphers = [
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES256-SHA384",
            "ECDHE-RSA-AES128-SHA256",
            "ECDHE-RSA-AES256-SHA",
            "ECDHE-RSA-AES128-SHA",
            "ECDHE-RSA-DES-CBC3-SHA",
            "AES256-GCM-SHA384",
            "AES128-GCM-SHA256",
            "AES256-SHA256",
            "AES128-SHA256",
            "AES256-SHA",
            "AES128-SHA",
            "DES-CBC3-SHA",
        ]
        ssl_context.set_ciphers(":".join(ciphers))
        return ssl_context

    async def start(self):
        lp = f"{self.lp}start:"
        logger.debug(
            f"{lp} Creating SSL context - key: {self.key_file}, cert: {self.cert_file}"
        )
        try:
            self.ssl_context = await self.create_ssl_context()
            self._server = await asyncio.start_server(
                self._register_new_connection,
                host=self.host,
                port=self.port,
                ssl=self.ssl_context,  # Pass the SSL context to enable SSL/TLS
            )
        except asyncio.CancelledError as ce:
            logger.debug(f"{lp} Server start cancelled: {ce}")
            # propagate the cancellation
            raise ce
        except Exception as e:
            logger.exception("%s Failed to start server: %s" % (lp, e))
            raise
        else:
            logger.info(
                f"{lp} bound to {self.host}:{self.port} - Waiting for connections from Cync devices, if you dont"
                f" see any, check your DNS redirection, VLAN and firewall settings."
            )
            self.running = True
            for home_id in self.node_devices.home_ids():
                self.start_home_grace(home_id)
            try:
                if g.mqtt_client:
                    await g.mqtt_client.publish(
                        f"{g.env.mqtt_topic}/status/bridge/tcp_server/running",
                        "ON".encode(),
                    )
                async with self._server:
                    await self._server.serve_forever()
            except asyncio.CancelledError as ce:
                raise ce
            except Exception as e:
                logger.exception("%s Server Exception: %s" % (self.lp, e))
                raise
            else:
                logger.debug(
                    f"{lp} DEBUG>>> AFTER self._server.serve_forever() <<<DEBUG"
                )

    async def stop(self):
        try:
            self.shutting_down = True
            lp = f"{self.lp}stop:"
            device: CyncTCPSession
            devices = list(self.tcp_connections.values())
            if devices:
                logger.debug(
                    f"{lp} Shutting down, closing connections to {len(devices)} devices..."
                )
                for device in devices:
                    try:
                        await device.close()
                    except asyncio.CancelledError as ce:
                        logger.debug(f"{lp} Device close cancelled: {ce}")
                        # propagate the cancellation
                        raise ce
                    except Exception as e:
                        logger.exception(
                            "%s Error closing Cync Wi-Fi device connection: %s"
                            % (lp, e)
                        )
                    else:
                        logger.debug(f"{lp} Cync Wi-Fi device connection closed")
            else:
                logger.debug(f"{lp} No Cync Wi-Fi devices connected!")
            await self._stop_home_grace()

            if self._server:
                if self._server.is_serving():
                    logger.debug(f"{lp} shutting down NOW...")
                    self._server.close()
                    await self._server.wait_closed()
                    if g.mqtt_client:
                        await g.mqtt_client.publish(
                            f"{g.env.mqtt_topic}/status/bridge/tcp_server/running",
                            "OFF".encode(),
                        )
                    logger.debug(f"{lp} shut down!")
                else:
                    logger.debug(f"{lp} not running!")

        except asyncio.CancelledError as ce:
            logger.debug(f"{lp} Server stop cancelled: {ce}")
            # propagate the cancellation
            raise ce
        except Exception as e:
            logger.exception(f"{lp} Error during server shutdown: {e}")
        else:
            logger.info(f"{lp} Server stopped successfully.")
        finally:
            if self.start_task and not self.start_task.done():
                logger.debug(f"{lp} FINISHING: Cancelling start task")
                self.start_task.cancel()

    async def _register_new_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        dev2add = None
        client_addr: str = writer.get_extra_info("peername")[0]
        if client_addr in self.tcp_conn_attempts:
            self.tcp_conn_attempts[client_addr] += 1
        else:
            self.tcp_conn_attempts[client_addr] = 1
        stats.inc("connections_accepted")
        lp = f"{self.lp}new_conn:{client_addr}:"
        existing_device = await self.remove_tcp_device(client_addr)
        if existing_device is not None:
            _add_str = ""
            if not existing_device.mitm_mode:
                _add_str = " closing and"
                # the same session object carries on with the new socket - keep its MITM switch
                await existing_device.close(remove_mitm_button=False)
            logger.debug(
                f"{lp} Existing TCP session found, gracefully{_add_str} replacing..."
            )
        try:
            if existing_device is not None:
                # a session that was rejected before gets the max_clients / whitelist check on its first packet, like a
                # new one. Checking it here, before the new socket was attached, blackholed the old (already closed)
                # socket and leaked the new one: the device sat on a silent ESTABLISHED connection.
                existing_device.reader = reader
                existing_device.writer = writer
                existing_device.ip_address = client_addr
                await existing_device.existing_init()
                dev2add = existing_device
            else:
                dev2add = CyncTCPSession(reader, writer, client_addr, registry=self.node_devices)
            await self.add_tcp_device(dev2add)
        except asyncio.CancelledError as ce:
            logger.debug(f"{lp} Connection cancelled: {ce}")
            # propagate the cancellation
            raise ce
        except Exception as e:
            # boundary of a client_connected callback: log it, and don't leak the socket
            stats.inc("connection_setup_failures")
            logger.exception(f"{lp} Error creating new Cync Wi-Fi device: {e}")
            writer.close()
