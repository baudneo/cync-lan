import argparse
import asyncio
import logging
import logging.handlers
import signal
import sys
from functools import partial
from pathlib import Path
from typing import Optional

import uvloop

from cync_lan.cloud_api import CyncCloudAPI
from cync_lan.const import (
    CYNC_CONFIG_FILE_PATH,
    CYNC_DEBUG,
    CYNC_ENABLE_EXPORTER,
    CYNC_LOG_NAME,
    CYNC_SECRET_KEY,
    CYNC_VERSION,
    EXPORT_SRV_START_TASK_NAME,
    FOREIGN_LOG_FORMATTER,
    LOG_FORMATTER,
    MQTT_CLIENT_START_TASK_NAME,
    nCYNC_START_TASK_NAME,
)
from cync_lan.exporter import ExportServer
from cync_lan.mqtt_client import MQTTClient
from cync_lan.server import nCyncServer
from cync_lan.structs import GlobalObject
from cync_lan.utils import (
    check_for_uuid,
    check_python_version,
    parse_config,
    send_sigterm,
    signal_handler,
)

logger = logging.getLogger(CYNC_LOG_NAME)
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.INFO)
stdout_handler.setFormatter(LOG_FORMATTER)
foreign_handler = logging.StreamHandler(sys.stderr)
foreign_handler.setLevel(logging.INFO)
foreign_handler.setFormatter(FOREIGN_LOG_FORMATTER)
uv_handler = logging.StreamHandler(sys.stdout)
uv_handler.setLevel(logging.INFO)
uv_handler.setFormatter(
    logging.Formatter(
        "%(asctime)s.%(msecs)d %(levelname)s (%(name)s) > %(message)s",
        "%m/%d/%y %H:%M:%S",
    )
)
logger.addHandler(stdout_handler)
logger.setLevel(logging.INFO)
# Control uvicorn logging, what a mess!
uvi_logger = logging.getLogger("uvicorn")
uvi_error_logger = logging.getLogger("uvicorn.error")
uvi_access_logger = logging.getLogger("uvicorn.access")
uvi_loggers = (uvi_logger, uvi_error_logger, uvi_access_logger)
for _ul in uvi_loggers:
    _ul.setLevel(logging.INFO)
    _ul.propagate = False
    _ul.addHandler(uv_handler)
mqtt_logger = logging.getLogger("mqtt")
# shut off the 'There are x pending publish calls.' from the mqtt logger (WARNING level)
mqtt_logger.setLevel(logging.ERROR)
mqtt_logger.propagate = False
mqtt_logger.addHandler(foreign_handler)
# logger.debug(f"{lp} Logging all registered loggers: {logging.getLogger().manager.loggerDict.keys()}")
g = GlobalObject()


class CyncLAN:
    lp: str = "CyncLAN:"
    config_file: Optional[Path] = None
    _instance: Optional["CyncLAN"] = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        lp = f"{self.lp}init:"
        check_for_uuid()
        logger.info(f"{lp} CyncLAN (version: {CYNC_VERSION}) stack initializing...")

    async def start(self):
        """Start the Cync LAN server, MQTT client, and Export server."""
        lp = f"{self.lp}start:"
        g.loop = asyncio.get_event_loop()
        g.loop.add_signal_handler(signal.SIGINT, partial(signal_handler, signal.SIGINT))
        g.loop.add_signal_handler(
            signal.SIGTERM, partial(signal_handler, signal.SIGTERM)
        )
        self.config_file = cfg_file = Path(CYNC_CONFIG_FILE_PATH).expanduser().resolve()
        tasks = []

        if cfg_file.exists():
            g.ncync_server = nCyncServer(await parse_config(cfg_file))
            g.mqtt_client = MQTTClient()
            g.ncync_server.start_task = n_start = asyncio.Task(
                g.mqtt_client.start(), name=MQTT_CLIENT_START_TASK_NAME
            )
            g.mqtt_client.start_task = m_start = asyncio.Task(
                g.ncync_server.start(), name=nCYNC_START_TASK_NAME
            )
            tasks.extend([n_start, m_start])
        else:
            logger.error(
                f"{lp} Cync config file not found at {cfg_file.as_posix()}. Please migrate "
                f"an existing config file or visit the ingress page and perform a device export."
            )
        if CYNC_ENABLE_EXPORTER is True:
            if not CYNC_SECRET_KEY:
                logger.critical(
                    f"{lp} You must set an non-empty, alphanumeric CYNC_SECRET_KEY env var to use the export server. Exiting..."
                )
                signal.raise_signal(signal.SIGTERM)
                sys.exit(55)
            g.cloud_api = CyncCloudAPI()
            g.export_server = ExportServer()
            g.export_server.start_task = x_start = asyncio.Task(
                g.export_server.start(), name=EXPORT_SRV_START_TASK_NAME
            )
            tasks.append(x_start)

        try:
            # the components start() methods have long running tasks of their own
            await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            logger.exception(f"{lp} Exception occurred while starting services: {e}")
            # Stop all services if any service fails to start
            await self.stop()
            raise e

    async def stop(self):
        """Stop the nCync server, MQTT client, and Export server."""
        lp = f"{self.lp}stop:"
        logger.info(f"{lp} Bringing software stack down using SIGTERM...")
        send_sigterm()


def parse_cli():
    parser = argparse.ArgumentParser(description="Cync LAN Server")

    parser.add_argument("-V", "--version", action="version", version=CYNC_VERSION)

    parser.add_argument(
        "-D",
        "--debug",
        action="store_true",
        help="Enable debug mode",
    )
    parser.add_argument(
        "--env", help="Path to the environment file", default=None, type=Path
    )
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)
        logger.debug("Debug mode enabled via CLI argument")
    if args.env:
        env_path = args.env
        env_path = env_path.expanduser().resolve()
        try:
            import dotenv

            loaded_any = dotenv.load_dotenv(env_path, override=True)
        except ImportError:
            logger.error(
                "dotenv module is not installed. Please install it with 'pip install python-dotenv'"
            )
        except Exception as e:
            logger.error(f"Failed to read environment file {env_path}: {e}")
        else:
            if not env_path.exists():
                logger.error(f"Environment file {env_path} does not exist")
            if loaded_any:
                logger.info(f"Environment variables loaded from {env_path}")
                g.reload_env()
            else:
                logger.warning(f"No environment variables were loaded from {env_path}")


def main():
    lp = "main:"
    parse_cli()
    if CYNC_DEBUG:
        logger.info(f"{lp} App config has set logging level to: Debug")
        logger.setLevel(logging.DEBUG)
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)
    check_python_version()
    loop = uvloop.new_event_loop()
    asyncio.set_event_loop(loop)
    g.cync_lan = CyncLAN()
    g.loop = loop
    try:
        loop.run_until_complete(g.cync_lan.start())
    except asyncio.CancelledError as e:
        logger.info(f"{lp} CyncLAN async stack cancelled: {e}")
    except KeyboardInterrupt:
        logger.info(f"{lp} Caught KeyboardInterrupt, exiting...")
    except Exception as e:
        logger.exception(f"{lp} Caught exception: {e}")
    else:
        logger.info(f"{lp} CyncLAN stack stopped gracefully, bye!")
    finally:
        if g.loop is not None:
            if not g.loop.is_closed():
                g.loop.close()
