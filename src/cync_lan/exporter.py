"""FastAPI application for exporting Cync device configuration from the Cync Cloud API."""

import asyncio
import logging
import os
from pathlib import Path
from typing import Optional

import aiohttp
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from cync_lan.const import (
    CYNC_CONFIG_FILE_PATH,
    CYNC_EXPORT_HOST,
    CYNC_EXPORT_PORT,
    CYNC_EXPORT_SOURCE,
    CYNC_LOG_NAME,
    CYNC_STATIC_DIR,
)
from cync_lan.structs import GlobalObject

g = GlobalObject()
logger = logging.getLogger(CYNC_LOG_NAME)


class OTPRequest(BaseModel):
    otp: int


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Or set to your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount(
    "/static",
    StaticFiles(directory=Path(CYNC_STATIC_DIR).expanduser().resolve()),
    name="static",
)


@app.get("/", response_class=HTMLResponse)
async def get_index():
    with Path(CYNC_STATIC_DIR + "/index.html").expanduser().resolve().open("r") as f:
        return f.read()


@app.get("/api/export/start")
async def start_export():
    ret_msg = "Export started successfully"
    if CYNC_EXPORT_SOURCE is None:
        try:
            succ = await g.cloud_api.check_token()
            if succ is False:
                req_succ = await g.cloud_api.request_otp()
                if req_succ is True:
                    ret_msg = "OTP requested, check your email for the OTP code to complete the export."
                    return {"success": False, "message": ret_msg}
                else:
                    ret_msg = "Failed to request OTP. Please check your credentials or network connection."
                    return {"success": False, "message": ret_msg}
        except Exception as e:
            logger.exception(f"Export start failed: {e}")
            raise HTTPException(status_code=400, detail=str(e))
    else:
        ret_msg = "CYNC_EXPORT_SOUCE configured, reading from a file instead of the cloud API."

    await g.cloud_api.export_config_file()
    return {"success": True, "message": ret_msg}


@app.get("/api/export/otp/request")
async def request_otp():
    """Request OTP for export."""
    ret_msg = "OTP requested successfully"
    try:
        otp_succ = await g.cloud_api.request_otp()
        if otp_succ:
            return {"success": True, "message": ret_msg}
        else:
            ret_msg = "Failed to request OTP. Please check your credentials or network connection."
            return {"success": False, "message": ret_msg}
    except Exception as e:
        logger.exception(f"OTP request failed: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/restart")
async def restart():
    #FIXME: non HASS app needs a sigterm
    lp = "ExportServer:restart:"
    supervisor_token = os.environ.get("SUPERVISOR_TOKEN")
    if not supervisor_token:
        logger.info(f"{lp} No SUPERVISOR_TOKEN found trying: cync_lan.stop()...")
        g.cync_lan.stop()
    else:
        # The 'self' slug is a special value that refers to the current App.
        # This is the recommended endpoint for self-restarts.
        url = "http://supervisor/addons/self/restart"

        headers = {
            "Authorization": f"Bearer {supervisor_token}",
            "Content-Type": "application/json",
        }
        logger.info(f"{lp} Attempting to restart App via API call to {url}...")

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers) as response:
                    if response.status == 200:
                        logger.debug(
                            f"{lp} Successfully called the restart API. The App will now restart."
                        )
                        return True, "App is restarting."
                    else:
                        # Try to get more details from the response if it fails
                        error_details = await response.text()
                        logger.warning(
                            f"{lp} Error: Failed to restart App. API returned status {response.status}"
                        )
                        logger.warning(f"{lp} Response: {error_details}")
                        return (
                            False,
                            f"API returned status {response.status}: {error_details}",
                        )

        except aiohttp.ClientError as e:
            logger.error(f"{lp} Error: An aiohttp client error occurred: {e}")
            return False, f"AIOHTTP Client Error: {e}"
        except Exception as e:
            logger.error(f"{lp} An unexpected error occurred: {e}")
            return False, f"An unexpected error occurred: {e}"


@app.post("/api/export/otp/submit")
async def submit_otp(otp_request: OTPRequest):
    ret_msg = "Export completed successfully"
    export_succ = False
    try:
        otp_succ = await g.cloud_api.send_otp(otp_request.otp)
        if otp_succ:
            export_succ = await g.cloud_api.export_config_file()
            if not export_succ:
                ret_msg = "Failed to complete export after OTP verification."
                return {"success": False, "message": ret_msg}
        else:
            ret_msg = "Invalid OTP. Please try again."

    except Exception as e:
        logger.exception(f"Export completion failed: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    else:
        return {"success": export_succ, "message": ret_msg}


@app.get("/api/healthcheck")
async def health_check():
    """Health check endpoint to verify if the server is running."""
    return {"status": "ok", "message": "Cync Export Server is running"}


@app.get("/api/export/download")
async def download_config():
    config_path = CYNC_CONFIG_FILE_PATH
    if os.path.exists(config_path):
        return FileResponse(config_path, filename="cync_mesh.yaml")
    raise HTTPException(status_code=404, detail="Config file not found")


class ExportServer:
    lp = "ExportServer:"
    enabled: bool = False
    running: bool = False
    start_task: Optional[asyncio.Task] = None
    _instance: Optional["ExportServer"] = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        self.app = app
        self.uvi_config: uvicorn.Config = uvicorn.Config(
            app,
            host=CYNC_EXPORT_HOST,
            port=CYNC_EXPORT_PORT,
            log_config={
                "version": 1,
                "disable_existing_loggers": False,
            },
            log_level="info",
        )
        self.uvi_server: uvicorn.Server = uvicorn.Server(config=self.uvi_config)

    async def start(self):
        """Start the FastAPI server."""
        lp = f"{self.lp}start:"
        logger.info(
            f"{lp} Starting FastAPI export server on {CYNC_EXPORT_HOST}:{CYNC_EXPORT_PORT}"
        )
        self.running = True
        # ["state_topic"] = f"{self.topic}/status/bridge/export_server/running"
        if g.mqtt_client:
            await g.mqtt_client.publish(
                f"{g.env.mqtt_topic}/status/bridge/export_server/running", "ON".encode()
            )
        try:
            await self.uvi_server.serve()
        except asyncio.CancelledError as ce:
            logger.info(f"{lp} FastAPI export server stopped")
            raise ce
        except Exception as e:
            logger.exception(f"{lp} Error starting FastAPI export server: {e}")
        else:
            logger.info(f"{lp} FastAPI export server lifecycle completed successfully")

    async def stop(self):
        """Stop the FastAPI server."""
        lp = f"{self.lp}stop:"
        logger.info(f"{lp} Stopping FastAPI export server...")
        try:
            await self.uvi_server.shutdown()
        except asyncio.CancelledError as ce:
            logger.info(f"{lp} FastAPI export server shutdown cancelled")
            raise ce
        except Exception as e:
            logger.exception(f"{lp} Error stopping FastAPI export server: {e}")
        else:
            self.running = False
        finally:
            if g.mqtt_client:
                await g.mqtt_client.publish(
                    f"{g.env.mqtt_topic}/status/bridge/export_server/running",
                    "OFF".encode(),
                )
                if self.start_task and not self.start_task.done():
                    logger.debug(f"{lp} FINISHING: Cancelling start task")
                    self.start_task.cancel()
