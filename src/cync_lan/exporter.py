"""FastAPI application for exporting Cync device configuration from the Cync Cloud API."""

import asyncio
import hashlib
import hmac
import logging
import os
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import aiohttp
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from cync_lan.const import (
    CYNC_CONFIG_FILE_PATH,
    CYNC_EXPORT_HOST,
    CYNC_EXPORT_PORT,
    CYNC_EXPORT_SOURCE,
    CYNC_EXPORT_TOKEN,
    CYNC_HASS_APP,
    CYNC_LOG_NAME,
    CYNC_SECRET_KEY,
    CYNC_STATIC_DIR,
)
from cync_lan.structs import GlobalObject

g = GlobalObject()
logger = logging.getLogger(CYNC_LOG_NAME)


class OTPRequest(BaseModel):
    otp: str


app = FastAPI()

# what talking to the Cync cloud / reading or writing the export can raise; anything else is a bug and
# becomes a logged 500 instead of being reported to the user as a bad request
_CLOUD_ERRORS = (RuntimeError, aiohttp.ClientError, OSError, TimeoutError, ValueError)

# The web UI is served by this app, so every legitimate browser request is same-origin and no
# CORS is needed. (It used to allow every origin with credentials, which let any website the
# user visited drive this LAN service.) Extra origins, e.g. behind a reverse proxy that rewrites
# the Host header, can be allowed with CYNC_EXPORT_ALLOWED_ORIGINS="https://a.example,https://b".
_EXTRA_ORIGINS = {
    o.strip().rstrip("/").lower()
    for o in os.environ.get("CYNC_EXPORT_ALLOWED_ORIGINS", "").split(",")
    if o.strip()
}


def origin_allowed(origin: Optional[str], host: Optional[str]) -> bool:
    """
    Cross-site request check. Browsers attach an Origin header to cross-origin requests and to
    same-origin POSTs; non-browser clients (curl, healthchecks) send none and are allowed.
    """
    if not origin:
        return True
    origin = origin.rstrip("/").lower()
    if origin in _EXTRA_ORIGINS:
        return True
    if origin == "null":
        return False
    return urlparse(origin).netloc == (host or "").lower()


def export_token() -> Optional[str]:
    """
    Access token for /api/*: CYNC_EXPORT_TOKEN if set, otherwise derived from CYNC_SECRET_KEY
    (so there is nothing extra to configure, and the secret itself is never sent over HTTP).
    """
    if CYNC_EXPORT_TOKEN:
        return CYNC_EXPORT_TOKEN
    if CYNC_SECRET_KEY:
        mac = hmac.new(CYNC_SECRET_KEY.encode(), b"cync-lan-export-ui-v1", hashlib.sha256)
        return mac.hexdigest()[:32]
    return None


def token_ok(auth_header: Optional[str], expected: Optional[str]) -> bool:
    """True if ``Authorization: Bearer <token>`` matches. No configured token means deny."""
    if not expected or not auth_header:
        return False
    scheme, _, value = auth_header.partition(" ")
    return scheme.lower() == "bearer" and hmac.compare_digest(
        value.strip().encode(), expected.encode()
    )


# the UI shell (/, /static) holds no secrets; the health check reveals nothing
_PUBLIC_API = {"/api/healthcheck"}


@app.middleware("http")
async def protect_api(request: Request, call_next):
    # Home Assistant ingress is already authenticated by the supervisor and rewrites Host
    if not CYNC_HASS_APP:
        if not origin_allowed(request.headers.get("origin"), request.headers.get("host")):
            logger.warning(
                f"ExportServer: blocked cross-site request from origin "
                f"{request.headers.get('origin')!r} to {request.url.path}"
            )
            return JSONResponse({"detail": "cross-site request blocked"}, status_code=403)
        path = request.url.path
        if path.startswith("/api/") and path not in _PUBLIC_API:
            if not token_ok(request.headers.get("authorization"), export_token()):
                return JSONResponse(
                    {"detail": "missing or invalid access token"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )
    return await call_next(request)


_static_dir = Path(CYNC_STATIC_DIR).expanduser().resolve()
if os.path.isdir(_static_dir):
    app.mount("/static", StaticFiles(directory=_static_dir), name="static")
else:
    logger.warning(f"ExportServer: static dir {_static_dir} does not exist, the web UI will not load")


@app.get("/", response_class=HTMLResponse)
async def get_index():
    with Path(CYNC_STATIC_DIR + "/index.html").expanduser().resolve().open("r") as f:
        return f.read()


@app.post("/api/export/start")
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
        except _CLOUD_ERRORS as e:
            logger.exception(f"Export start failed: {e}")
            raise HTTPException(status_code=400, detail=str(e)) from e
    else:
        ret_msg = "CYNC_EXPORT_SOUCE configured, reading from a file instead of the cloud API."

    try:
        exported = await g.cloud_api.export_config_file()
    except _CLOUD_ERRORS as e:
        logger.exception(f"Export failed: {e}")
        raise HTTPException(status_code=502, detail=str(e)) from e
    if not exported:
        return {"success": False, "message": "Export failed, see the cync-lan log for details."}
    return {"success": True, "message": ret_msg}


@app.post("/api/export/otp/request")
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
    except _CLOUD_ERRORS as e:
        logger.exception(f"OTP request failed: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e)) from e


@app.post("/api/restart")
async def restart():
    # FIXME: non HASS app needs a sigterm
    lp = "ExportServer:restart:"
    if CYNC_HASS_APP is True:
        supervisor_token = os.environ.get("SUPERVISOR_TOKEN")
        if not supervisor_token:
            logger.info(f"{lp} No SUPERVISOR_TOKEN found trying: cync_lan.stop()...")
            await g.cync_lan.stop()
            return {"success": True, "message": "Shutting down, the container/service manager should restart it."}
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
                timeout = aiohttp.ClientTimeout(total=10)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(url, headers=headers) as response:
                        if response.status == 200:
                            logger.debug(
                                f"{lp} Successfully called the restart API. The App will now restart."
                            )
                            return {"success": True, "message": "App is restarting."}
                        else:
                            # Try to get more details from the response if it fails
                            error_details = await response.text()
                            logger.warning(
                                f"{lp} Error: Failed to restart App. API returned status {response.status}"
                            )
                            logger.warning(f"{lp} Response: {error_details}")
                            raise HTTPException(
                                status_code=502,
                                detail=f"API returned status {response.status}: {error_details}",
                            )

            except HTTPException:
                raise
            except (aiohttp.ClientError, TimeoutError) as e:
                logger.error(f"{lp} Error: An aiohttp client error occurred: {e!r}")
                raise HTTPException(status_code=502, detail=f"Supervisor request failed: {e!r}") from e
            except Exception as e:
                logger.error(f"{lp} An unexpected error occurred: {e}")
                raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {e}") from e
    else:
        logger.info(f"{lp} Trying: cync_lan.stop()...")
        await g.cync_lan.stop()
        return {"success": True, "message": "Shutting down, the container/service manager should restart it."}


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

    except _CLOUD_ERRORS as e:
        logger.exception(f"Export completion failed: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e)) from e
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
        if not CYNC_HASS_APP:
            if CYNC_EXPORT_TOKEN:
                logger.info(f"{lp} The export web app requires the access token from CYNC_EXPORT_TOKEN")
            elif export_token():
                logger.info(
                    f"{lp} The export web app asks for an access token, enter: {export_token()}"
                )
            else:
                logger.error(f"{lp} No CYNC_EXPORT_TOKEN or CYNC_SECRET_KEY set, all /api routes will be denied")
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
            raise
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
