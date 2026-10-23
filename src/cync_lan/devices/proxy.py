import asyncio
import datetime
import logging
import logging.handlers
import os
import ssl
import sys
import time
from pathlib import Path

from cync_lan.const import (
    CYNC_CLOUD_IP,
    CYNC_LOG_NAME,
    CYNC_MAX_TCP_CONN,
    CYNC_MITM_APP_LOGGER,
    CYNC_MITM_DEV_LOGGER,
    CYNC_MITM_LOG_DIR,
    CYNC_TCP_WHITELIST,
    STREAM_CHUNK_SIZE,
    TCP_BLACKHOLE_DELAY,
)
from cync_lan.structs import (
    ConnectionType,
    GlobalObject,
)
from cync_lan.utils import format_socat_style

__all__ = ["ProxyMixin"]
logger = logging.getLogger(CYNC_LOG_NAME)
g = GlobalObject()


class ProxyMixin:
    """Cloud proxy / MITM logging / connection gating for a CyncTCPSession."""

    async def start_proxy(self):
        lp = f"{self.lp}start proxy:"
        try:
            ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            logger.info(
                f"{lp} Connecting to Cync Cloud via IP ({CYNC_CLOUD_IP}:23779)..."
            )
            self.cloud_reader, self.cloud_writer = await asyncio.open_connection(
                CYNC_CLOUD_IP, 23779, ssl=ssl_context
            )
            self.tasks.proxy_task = asyncio.create_task(
                self._cloud_proxy_task(),
                name=f"proxy_task-{self.ip_address}_ID:{self.node.id}",
            )
            self.tasks.proxy_conn_watcher = asyncio.create_task(
                self.connection_watcher_task(ConnectionType.proxy),
                name=f"proxy_connection_watcher-{self.ip_address}"
            )
        except (OSError, TimeoutError) as e:
            logger.error(f"{lp} Failed to start MITM: {e!r}")
            await self.stop_proxy()

    async def start_mitm(self):
        """Connect to Cync Cloud and start proxying."""
        lp = f"{self.lp}mitm:start:"
        if self.mitm_mode and self.cloud_writer:
            logger.debug(
                f"{lp} MITM is already set to True and active, skipping starting of mitm mode..."
            )
            return
        self._setup_mitm_logger()
        try:
            await self.start_proxy()
            logger.info(
                f"{lp} MITM mode enabled, closing TCP connection to force device to reconnect and handshake with cloud through this proxy..."
            )
            # close the conneciton but dont remove the mitm button
            asyncio.create_task(self.close(False))
        except asyncio.CancelledError:
            logger.debug(f"{lp} start_mitm task was cancelled...")
        except (OSError, TimeoutError) as e:
            logger.exception(f"{lp} Failed to start MITM: {e!r}")

        else:
            self.mitm_mode = True

    def is_proxy_good(self):
        if self.tasks.proxy_task and not self.tasks.proxy_task.done():
            logger.debug(f"{self.lp} Proxy task is active!")
        elif not self.tasks.proxy_task:
            logger.debug(f"{self.lp} Proxy receive task is None, need to restart...")
            return False
        elif self.tasks.proxy_task.done():
            logger.debug(f"{self.lp} Proxy receive task is done, need to restart...")
            return False

        if self.tasks.proxy_conn_watcher and not self.tasks.proxy_conn_watcher.done():
            logger.debug(f"{self.lp} Proxy connection watcher task is active!")
        elif not self.tasks.proxy_conn_watcher:
            logger.debug(f"{self.lp} Proxy connection watcher task is None, need to restart...")
            return False
        elif self.tasks.proxy_conn_watcher.done():
            logger.debug(f"{self.lp} Proxy connection watcher task is done, need to restart...")
            return False

        if self.cloud_reader:
            logger.debug(f"{self.lp} Cloud reader is active!")
        else:
            logger.debug(f"{self.lp} Cloud reader is None, need to restart...")
            return False

        if self.cloud_writer:
            logger.debug(f"{self.lp} Cloud writer is active!")
        else:
            logger.debug(f"{self.lp} Cloud writer is None, need to restart...")
            return False

        return True

    async def stop_proxy(self):
        lp = f"{self.lp}stop proxy:"
        if self.tasks.proxy_task and not self.tasks.proxy_task.done():
            logger.debug(f"{lp} Cancelling proxy task...")
            self.tasks.proxy_task.cancel()
            try:
                await self.tasks.proxy_task
            except (asyncio.CancelledError, OSError):
                # CancelledError is what awaiting a cancelled task raises; `except Exception` let it
                # escape and aborted the rest of the teardown
                pass
        self.tasks.proxy_task = None
        logger.debug(f"{lp} Proxy task stopped")

        if self.tasks.proxy_conn_watcher and not self.tasks.proxy_conn_watcher.done():
            logger.debug(f"{lp} Cancelling proxy connection watcher task...")
            self.tasks.proxy_conn_watcher.cancel()
            try:
                await self.tasks.proxy_conn_watcher
            except (asyncio.CancelledError, OSError):
                pass
            self.tasks.proxy_conn_watcher = None
            logger.debug(f"{lp} Proxy connection watcher task stopped")

        if self.cloud_reader:
            try:
                self.cloud_reader.feed_eof()
                logger.debug(f"{lp} Fed eof to cloud_reader")
            except (AttributeError, RuntimeError) as e:
                logger.debug(f"{lp} Cloud reader feed_eof error (ignored): {e}")
        self.cloud_reader = None

        if self.cloud_writer:
            logger.debug(f"{lp} Closing cloud writer...")
            try:
                self.cloud_writer.close()
                await asyncio.wait_for(self.cloud_writer.wait_closed(), timeout=5.0)
                logger.debug(f"{lp} Cloud writer closed cleanly")
            except asyncio.TimeoutError:
                logger.warning(f"{lp} Cloud writer.wait_closed() timed out, continuing anyway")
            except (OSError, RuntimeError) as e:
                logger.debug(f"{lp} Cloud writer close error (ignored): {e}")
        self.cloud_writer = None

        self.mitm_bytes_to_cloud = 0
        self.mitm_bytes_from_cloud = 0
        logger.debug(f"{lp} Proxy closed!")

    async def stop_mitm(self):
        """Close cloud connection and stop proxying."""
        lp = f"{self.lp}close mitm:"
        logger.debug(f"{lp} closing...")
        # if self.mitm is True or self.cloud_reader or self.cloud_writer:
        await self.stop_proxy()
        self.mitm_mode = False
        self.mitm_logger = None
        logger.info(f"{self.lp} MITM Mode disabled, forcing disconnect to enable normal operation...")
        await self.close()

    async def _cloud_proxy_task(self):
        """Reads from cloud and writes to device."""
        lp = f"{self.lp}mitm:proxy:"
        logger.debug(f"{lp} listening for data from the Cync cloud...")
        try:
            while self.cloud_reader:
                data = await self.cloud_reader.read(STREAM_CHUNK_SIZE)
                if not data:
                    pass
                else:
                    self.proxy_last_packet_ts = time.time()
                    self.mitm_logger.debug(
                        format_socat_style(
                            data, "from_cloud", self.ip_address, self.mitm_bytes_from_cloud
                        )
                    )
                    self.mitm_bytes_from_cloud += len(data)
                    self.writer.write(data)
                    await self.writer.drain()
        except asyncio.CancelledError:
            logger.debug(f"{lp} Cloud proxy task CANCELED cleanly, re-raising...")
            raise
        except Exception as e:
            logger.error(f"{lp} Error in cloud proxy: {e!r}", exc_info=not isinstance(e, OSError))

        logger.debug(f"{lp} FINISHED")

    def _setup_mitm_logger(self):
        """Initializes a rotating file logger for this specific connection."""
        lp = f"{self.lp}mitm logger:"
        if self.mitm_logger:
            logger.debug(
                f"{lp} Already setup for Node: '{self.name}' (ID: {self.node.id})"
            )
            return
        # Differentiate between App (by IP) and Device (by ID)
        conn_type = "dev"
        if self.is_app:
            conn_type = "app"
            identifier = f"{conn_type}_{self.ip_address.replace('.', '-')}"
        elif self.node:
            identifier = f"{conn_type}_{self.node.id}"
        logger_name = f"MITM {conn_type}:{self.ip_address}"
        mitm_logger = logging.getLogger(logger_name)
        self.mitm_logger = mitm_logger
        if self.is_app and not g.env.app_mitm_logging:
            logger.warning(f"{lp} This is an App TCP connection and global App MITM logging is disabled, "
                           f"not logging this proxied connection...")
            return
        self.log_start_time = datetime.datetime.now().strftime("%Y%m%d")
        log_dir = Path(CYNC_MITM_LOG_DIR)
        log_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(log_dir, 0o777)
        log_file = log_dir / f"mitm_{identifier}-{self.log_start_time}.log"
        formatter = logging.Formatter(
            "%(asctime)s.%(msecs)03d [%(name)s] %(message)s", datefmt="%Y/%m/%d %H:%M:%S"
        )

        self.mitm_logger.setLevel(logging.DEBUG)
        self.mitm_logger.propagate = False

        file_handler = logging.handlers.TimedRotatingFileHandler(log_file, when="midnight")
        file_handler.setFormatter(formatter)
        self.mitm_logger.addHandler(file_handler)
        if (CYNC_MITM_DEV_LOGGER and not self.is_app) or (CYNC_MITM_APP_LOGGER and self.is_app):
            stdout_handler = logging.StreamHandler(sys.stdout)
            stdout_handler.setLevel(logging.DEBUG)
            stdout_handler.setFormatter(formatter)
            self.mitm_logger.addHandler(stdout_handler)
        os.chmod(log_file, 0o777)
        logger.debug(
            f"Created a MITM logger for node: '{self.name}' (ID: {self.node.id}) -> {log_file}"
        )

    async def blackhole(self, reason: str, should_sleep: bool):
        lp = f"{self.lp}"
        if should_sleep is True:
            await asyncio.sleep(TCP_BLACKHOLE_DELAY)
        try:
            self.reader.feed_eof()
            self.writer.close()
            task = asyncio.create_task(self.writer.wait_closed())
            await asyncio.wait([task], timeout=5)
        except asyncio.CancelledError as ce:
            logger.debug(f"{lp} Task cancelled: {ce}")
            raise ce
        except (OSError, RuntimeError, AttributeError) as e:
            logger.error(f"{lp} Error closing reader/writer: {e!r}", exc_info=True)
        finally:
            self.reader = None
            self.writer = None
        return False

    async def can_connect(self) -> bool:
        """Based on TCP_WHITELIST and MAX_TCP_CONN, should only be used on Cync device connections"""
        lp = f"{self.lp}:can connect:"
        tcp_dev_len = len(g.ncync_server.tcp_connections)
        num_attempts = g.ncync_server.tcp_conn_attempts[self.ip_address]
        if self.mitm_mode:
            logger.debug(f"{lp} MITM active, skipping connection check...")
            self.allowed_to_connect = True

        elif (
            (g.ncync_server.shutting_down is True)
            or (tcp_dev_len >= CYNC_MAX_TCP_CONN)
            or (CYNC_TCP_WHITELIST and self.ip_address not in CYNC_TCP_WHITELIST)
        ):
            reason = ""
            if g.ncync_server.shutting_down is True:
                reason = "CyncLAN server is shutting down, "
            _sleep = False
            if tcp_dev_len >= CYNC_MAX_TCP_CONN:
                reason = f"CyncLAN server max ({tcp_dev_len}/{CYNC_MAX_TCP_CONN}) TCP connections reached, "
                _sleep = True
            elif CYNC_TCP_WHITELIST and self.ip_address not in CYNC_TCP_WHITELIST:
                reason = f"IP not in CyncLAN server whitelist -> {CYNC_TCP_WHITELIST}, "
                _sleep = True
            # show a reminder every 20 reconnections
            tst_ = (num_attempts == 1) or (num_attempts % 20 == 1)
            lmsg = f"{lp} {reason}rejecting new connection..."
            if tst_:
                logger.warning(lmsg)
            self.allowed_to_connect = False
            await self.blackhole(reason, _sleep)

        else:
            self.allowed_to_connect = True

        return self.allowed_to_connect
