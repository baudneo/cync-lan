import asyncio
import logging
import ssl
import time
from typing import Dict, Optional, Union

import uvloop

from cync_lan.const import CYNC_LOG_NAME, CYNC_SRV_HOST, CYNC_SRV_PORT
from cync_lan.devices import CyncDevice, CyncTCPSession
from cync_lan.structs import EntityState, GlobalObject

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

    node_devices: Dict[int, CyncDevice] = {}
    tcp_connections: Dict[str, Optional[CyncTCPSession]] = {}
    app_tcp_connections: Dict[str, Optional[CyncTCPSession]] = {}
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

    def __init__(self, node_map: Dict[int, "CyncDevice"]):
        self.node_devices: Dict[int, "CyncDevice"] = node_map
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
        app_ips = [d.ip_address for d in apps]
        # todo: add app ip addresses as an attribute
        await g.mqtt_client.publish(
            f"{g.env.mqtt_topic}/status/bridge/apps/connected", str(len(apps)).encode()
        )

        devs = self.tcp_connections.values()
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
        else:
            logger.info(
                f"{lp} bound to {self.host}:{self.port} - Waiting for connections from Cync devices, if you dont"
                f" see any, check your DNS redirection, VLAN and firewall settings."
            )
            self.running = True
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
        lp = f"{self.lp}new_conn:{client_addr}:"
        existing_device = await self.remove_tcp_device(client_addr)
        if existing_device is not None:
            _add_str = ""
            if not existing_device.mitm_mode:
                _add_str = " closing and"
                await existing_device.close()
            logger.debug(
                f"{lp} Existing TCP session found, gracefully{_add_str} replacing..."
            )
        try:
            if existing_device is not None:
                if existing_device.allowed_to_connect is False:
                    can_connect = existing_device.can_connect()
                    if can_connect is False:
                        del existing_device
                        existing_device = None
                        dev2add = None
                if existing_device is not None:
                    existing_device.reader = reader
                    existing_device.writer = writer
                    existing_device.ip_address = client_addr
                    existing_device.existing_init()
                    dev2add = existing_device
            else:
                dev2add = CyncTCPSession(reader, writer, client_addr)
            if dev2add is not None:
                await self.add_tcp_device(dev2add)
        except asyncio.CancelledError as ce:
            logger.debug(f"{lp} Connection cancelled: {ce}")
            # propagate the cancellation
            raise ce
        except Exception as e:
            logger.exception(f"{lp} Error creating new Cync Wi-Fi device: {e}")
