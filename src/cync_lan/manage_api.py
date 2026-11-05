"""
Web UI API for managing the Cync homes cync-lan knows: devices (rename, enable / disable, hybrid relay is read only
here), the Cync rooms (read only: they belong to the Cync account) and cync-lan's own local groups (create, edit,
delete, put on / take off the switches). Mounted on the export web app under /api/manage, so it is protected like the
rest of /api (HA ingress, or the access token).

Changes are written to cync_mesh.yaml (a backup of the previous file is kept next to it) and applied to the running
registry and Home Assistant at once, except enabling / disabling a device, which needs a restart.
"""
import asyncio
import logging
import shutil
import time
from pathlib import Path
from typing import Dict, List, Optional

import yaml
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from cync_lan.const import CYNC_CONFIG_FILE_PATH, CYNC_HYBRID_RELAY, CYNC_LOG_NAME
from cync_lan.devices.group import LOCAL_GROUP_MAX, LOCAL_GROUP_MIN, CyncGroup
from cync_lan.devices.registry import CONFIG_MAIN_KEYS, LOCAL_GROUPS_KEY, as_home_id
from cync_lan.metadata.model_info import device_type_map
from cync_lan.structs import GlobalObject
from cync_lan.utils import write_private_file

__all__ = ["router"]
logger = logging.getLogger(CYNC_LOG_NAME)
g = GlobalObject()
router = APIRouter(prefix="/api/manage")
_lock = asyncio.Lock()
BACKUPS_KEPT = 10
# background membership jobs, kept referenced until they finish
_jobs: set = set()


def _spawn(coro, name: str) -> asyncio.Task:
    task = asyncio.create_task(coro, name=name)
    _jobs.add(task)

    def done(t: asyncio.Task) -> None:
        _jobs.discard(t)
        if not t.cancelled() and t.exception() is not None:
            logger.error(f"manage: {name} failed: {t.exception()!r}")

    task.add_done_callback(done)
    return task


class LocalGroupIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    members: List[int]
    id: Optional[int] = None


class DeviceIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=64)
    enabled: Optional[bool] = None


# ---- helpers
def _registry():
    server = getattr(g, "ncync_server", None)
    if server is None or getattr(server, "node_devices", None) is None:
        raise HTTPException(503, "cync-lan is still starting")
    return server.node_devices


def _hybrid(device) -> bool:
    return "all" in CYNC_HYBRID_RELAY or device.hass_id.casefold() in CYNC_HYBRID_RELAY


def _device_json(registry, device) -> dict:
    session = getattr(device, "tcp_session", None)
    return {
        "id": device.id,
        "name": device.name,
        "type": device.type,
        "model": device_type_map[device.type].model_string if device.type in device_type_map else "Unknown",
        "online": bool(device.online),
        "bridge": session is not None and not session.is_closed(),
        "multi_way": bool(getattr(device, "multi_way", False)),
        "hybrid": _hybrid(device),
        "room": getattr(registry.room_of(device), "id", None),
        "groups": [gr.id for gr in registry.groups_with(device)],
        "reported_groups": getattr(device, "group_slots", None),
    }


def _group_json(group: CyncGroup) -> dict:
    return {
        "id": group.id,
        "name": group.name,
        "members": [m.id for m in group.members],
        "subgroup": group.is_subgroup,
        "local": group.is_local,
        "entity_id": f"light.cync_lan_{group.home_id}_group_{group.id}",
    }


def _home_or_404(registry, home_id: int) -> str:
    name = registry.home_name(home_id)
    if name is None or home_id not in registry.home_ids():
        raise HTTPException(404, f"no Cync home {home_id}")
    return name


def _read_config() -> dict:
    try:
        return yaml.safe_load(Path(CYNC_CONFIG_FILE_PATH).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError, UnicodeDecodeError) as exc:
        raise HTTPException(500, f"could not read the config file: {exc}") from exc


def _config_home(cfg: dict, home_id: int) -> dict:
    main = next((cfg[k] for k in CONFIG_MAIN_KEYS if isinstance(cfg.get(k), dict)), None)
    if main is None:
        raise HTTPException(500, "the config file has no exported_homes section")
    for home_cfg in main.values():
        if isinstance(home_cfg, dict) and as_home_id(home_cfg.get("id")) == home_id:
            return home_cfg
    raise HTTPException(404, f"home {home_id} is not in the config file")


def _write_config(cfg: dict) -> None:
    """Write the config back, keeping a timestamped backup of the previous file (the newest BACKUPS_KEPT)."""
    path = Path(CYNC_CONFIG_FILE_PATH)
    if path.exists():
        backup = path.with_name(f"{path.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}")
        shutil.copy2(path, backup)
        for old in sorted(path.parent.glob(f"{path.name}.bak-*"))[:-BACKUPS_KEPT]:
            old.unlink(missing_ok=True)
    # holds each home's access_key: private
    write_private_file(path, yaml.dump(cfg), 0o600)


def _check_members(registry, home_id: int, members: List[int]) -> List[int]:
    known = {d.id for d in registry.in_home(home_id)}
    bad = [m for m in members if m not in known]
    if bad:
        raise HTTPException(400, f"not devices of this home: {bad}")
    if not members:
        raise HTTPException(400, "a group needs at least one member")
    return sorted(set(members))


async def _mqtt(method: str, *args) -> None:
    client = getattr(g, "mqtt_client", None)
    if client is not None and getattr(client, "_connected", False):
        await getattr(client, method)(*args)


# ---- read
@router.get("/homes")
async def list_homes() -> List[dict]:
    registry = _registry()
    out = []
    for home_id in registry.home_ids():
        groups = [gr for gr in registry.groups() if gr.home_id == home_id]
        out.append({
            "id": home_id,
            "name": registry.home_name(home_id),
            "devices": [_device_json(registry, d) for d in registry.in_home(home_id)],
            "rooms": [_group_json(gr) for gr in groups if not gr.is_local],
            "local_groups": [_group_json(gr) for gr in groups if gr.is_local],
            "next_local_group_id": registry.next_local_group_id(home_id),
        })
    return out


# ---- local groups
@router.post("/homes/{home_id}/local_groups")
async def create_local_group(home_id: int, body: LocalGroupIn, sync: bool = True) -> dict:
    registry = _registry()
    async with _lock:
        home_name = _home_or_404(registry, home_id)
        members = _check_members(registry, home_id, body.members)
        group_id = body.id if body.id is not None else registry.next_local_group_id(home_id)
        if group_id is None or not LOCAL_GROUP_MIN <= group_id <= LOCAL_GROUP_MAX:
            raise HTTPException(400, f"group id must be {LOCAL_GROUP_MIN}-{LOCAL_GROUP_MAX}")
        if registry.get_group(home_id, group_id) is not None:
            raise HTTPException(409, f"group id {group_id} is already used in this home")
        cfg = _read_config()
        home_cfg = _config_home(cfg, home_id)
        home_cfg.setdefault(LOCAL_GROUPS_KEY, {})[group_id] = {"name": body.name, "members": members}
        _write_config(cfg)
        group = registry.add_group(CyncGroup(home_id, group_id, body.name, members, home_name=home_name, is_local=True))
    logger.info(f"manage: created local group '{body.name}' ({group_id:#06x}) in home {home_name}: {members}")
    await _mqtt("publish_group_discovery", group)
    if sync:
        _spawn(group.sync_members(registry), f"manage_sync-{group.hass_id}")
    return _group_json(group)


@router.put("/homes/{home_id}/local_groups/{group_id}")
async def update_local_group(home_id: int, group_id: int, body: LocalGroupIn, sync: bool = True) -> dict:
    registry = _registry()
    async with _lock:
        home_name = _home_or_404(registry, home_id)
        old = registry.get_group(home_id, group_id)
        if old is None or not old.is_local:
            raise HTTPException(404, f"no local group {group_id} in this home")
        members = _check_members(registry, home_id, body.members)
        cfg = _read_config()
        home_cfg = _config_home(cfg, home_id)
        home_cfg.setdefault(LOCAL_GROUPS_KEY, {})[group_id] = {"name": body.name, "members": members}
        _write_config(cfg)
        removed = [m for m in old.members if m.id not in members]
        group = registry.add_group(CyncGroup(home_id, group_id, body.name, members, home_name=home_name, is_local=True))
    logger.info(f"manage: updated local group '{body.name}' ({group_id:#06x}): {members}")
    await _mqtt("publish_group_discovery", group)
    if sync:
        async def apply():
            if removed:
                # the members that left: take the group off them (a group object holding just those members)
                leaving = CyncGroup(home_id, group_id, body.name, [m.id for m in removed], home_name, is_local=True)
                leaving.members = removed
                await leaving.remove_from_members(registry)
            await group.sync_members(registry)
        _spawn(apply(), f"manage_update-{group.hass_id}")
    return _group_json(group)


@router.delete("/homes/{home_id}/local_groups/{group_id}")
async def delete_local_group(home_id: int, group_id: int, remove_from_switches: bool = True) -> dict:
    registry = _registry()
    async with _lock:
        _home_or_404(registry, home_id)
        group = registry.get_group(home_id, group_id)
        if group is None or not group.is_local:
            raise HTTPException(404, f"no local group {group_id} in this home")
        cfg = _read_config()
        home_cfg = _config_home(cfg, home_id)
        (home_cfg.get(LOCAL_GROUPS_KEY) or {}).pop(group_id, None)
        if LOCAL_GROUPS_KEY in home_cfg and not home_cfg[LOCAL_GROUPS_KEY]:
            del home_cfg[LOCAL_GROUPS_KEY]
        _write_config(cfg)
    logger.info(f"manage: deleting local group '{group.name}' ({group_id:#06x})")
    await _mqtt("remove_group_discovery", group)

    async def apply():
        # remove from the switches first (it needs the group's membership), then forget it
        if remove_from_switches:
            await group.remove_from_members(registry)
        registry.remove_group(home_id, group_id)
    if remove_from_switches:
        _spawn(apply(), f"manage_delete-{group.hass_id}")
    else:
        registry.remove_group(home_id, group_id)
    return {"deleted": group_id}


@router.post("/homes/{home_id}/local_groups/{group_id}/{action}")
async def group_action(home_id: int, group_id: int, action: str) -> dict:
    registry = _registry()
    group = registry.get_group(home_id, group_id)
    if group is None or not group.is_local:
        raise HTTPException(404, f"no local group {group_id} in this home")
    if action == "sync":
        _spawn(group.sync_members(registry), f"manage_sync-{group.hass_id}")
    elif action == "remove":
        _spawn(group.remove_from_members(registry), f"manage_remove-{group.hass_id}")
    else:
        raise HTTPException(400, "action must be sync or remove")
    return {"started": action}


# ---- devices
@router.patch("/homes/{home_id}/devices/{dev_id}")
async def update_device(home_id: int, dev_id: int, body: DeviceIn) -> dict:
    registry = _registry()
    async with _lock:
        _home_or_404(registry, home_id)
        device = registry.get_device(home_id, dev_id)
        cfg = _read_config()
        home_cfg = _config_home(cfg, home_id)
        devices: Dict = home_cfg.get("devices") or {}
        dev_cfg = devices.get(dev_id, devices.get(str(dev_id)))
        if dev_cfg is None:
            raise HTTPException(404, f"no device {dev_id} in this home")
        restart = False
        if body.name is not None and body.name != dev_cfg.get("name"):
            old = dev_cfg.get("name")
            dev_cfg["name"] = body.name
            endpoints = dev_cfg.get("endpoints")
            if isinstance(endpoints, dict) and len(endpoints) == 1 and list(endpoints.values())[0] == old:
                endpoints[next(iter(endpoints))] = body.name
            if device is not None:
                device.name = body.name
                for ep in (device.entities or {}).values():
                    if len(device.entities) == 1:
                        ep.name = body.name
        if body.enabled is not None:
            was = dev_cfg.get("enabled", True) not in (False, "no", "false", "off")
            if body.enabled != was:
                dev_cfg["enabled"] = body.enabled
                restart = True
        _write_config(cfg)
    if body.name is not None:
        # names reach HA through discovery
        await _mqtt("homeassistant_discovery")
    return {"id": dev_id, "name": dev_cfg.get("name"), "enabled": dev_cfg.get("enabled", True),
            "restart_required": restart}
