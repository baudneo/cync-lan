"""
Multi-home device registry and home resolution.

Every Cync home is its own BLE mesh and mesh device ids restart at 1 in each home, so a bare
device id is not unique once an account has more than one home. Devices are therefore keyed by
``(home_id, dev_id)``. ``CyncDevice.id`` stays the per-home mesh id: it is what control packets
target.

A bridge (a Wi-Fi device holding a TCP session to this server) only relays its own home's mesh, and no
packet carries a home field. The first packet a device sends (0x23) does name the device itself: its 4-byte
queue id is the device's cloud ``switchID`` (confirmed on hardware, docs/protocol.md section 7), and the
exported config says which home that device is in. ``HomeResolver`` works the home out per session from
these signals, strongest first (see docs/multi_home.md):

  a) only one home is configured -> that home (single-home setups behave exactly as before);
  b) the session IP is listed in a home's optional ``bridges:`` list in cync_mesh.yaml;
  c) the 4-byte queue id from the 0x23 hello, read big-endian, equals a device's ``switch_id`` (written by
     the cloud export). The queue id is not the home id (confirmed on hardware), so homes are never matched by it;

There is no guessing from device ids: mesh ids are nested (1..N in every home), so they cannot tell homes apart
reliably. A bridge whose home none of these signals can name is left unresolved and never used for commands;
``unresolved_bridge_message`` tells the user how to fix it (re-export, or ``bridges:``).

Everything here is pure: no ``g``, no I/O, no logging inside the resolver. Callers log.
"""

import ipaddress
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from cync_lan.devices.device import CyncDevice

__all__ = [
    "BRIDGES_KEY",
    "SWITCH_ID_KEY",
    "DeviceKey",
    "DeviceRegistry",
    "HomeInfo",
    "HomeMatch",
    "HomeResolver",
    "as_home_id",
    "as_positive_int",
    "carry_over_bridges",
    "homes_for_queue_id",
    "normalize_ip",
    "parse_queue_id",
    "unresolved_bridge_message",
]

BRIDGES_KEY = "bridges"
"""Optional per-home config key: list of bridge IP strings (manual home override)."""
SWITCH_ID_KEY = "switch_id"
"""Optional per-device config key: the cloud ``switchID`` of the device (int, non-zero)."""
CONFIG_MAIN_KEYS = ("account data", "exported_homes")
"""Top-level sections a config can hold its homes in, in the order the config parser looks for them ('exported_homes'
is what the exporter writes; 'account data' is the legacy name). Every reader must use this one order."""

DeviceKey = Tuple[int, int]
"""(home_id, dev_id)"""

# resolution methods, in priority order
METHOD_SINGLE_HOME = "single_home"
METHOD_BRIDGES = "bridges"
METHOD_QUEUE_ID = "queue_id"


def normalize_ip(ip) -> Optional[str]:
    """Canonical text form of an IP address (strips whitespace), None when it is not an IP."""
    if not isinstance(ip, str):
        return None
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return None


@dataclass(frozen=True)
class HomeInfo:
    """Per-home metadata from the config file."""

    home_id: int
    name: str
    bridges: FrozenSet[str] = field(default_factory=frozenset)


class DeviceRegistry(dict):
    """
    All configured devices, keyed by ``(home_id, dev_id)``.

    A plain dict subclass so ``.values()``, ``len()`` and iteration keep working for code that only
    needs "every device". Use the helpers for lookups; a bare device id is ambiguous across homes.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._homes: Dict[int, HomeInfo] = {}

    # ---- building
    def add_home(self, home_id: int, name: str, bridges: Iterable[str] = ()) -> HomeInfo:
        """Register (or replace) a home's metadata. ``bridges`` entries that are not IPs are dropped."""
        ips = frozenset(ip for ip in (normalize_ip(b) for b in bridges) if ip is not None)
        info = HomeInfo(home_id=int(home_id), name=str(name), bridges=ips)
        self._homes[info.home_id] = info
        return info

    def add(self, device: "CyncDevice") -> None:
        """Add a device under ``device.key``; registers its home (named from the device) if needed."""
        if device.home_id is None:
            raise ValueError(f"device {device.id} has no home_id, it cannot be put in the registry")
        if device.home_id not in self._homes:
            self.add_home(device.home_id, device.home_name or str(device.home_id))
        self[device.key] = device

    # ---- devices
    def get_device(self, home_id: Optional[int], dev_id: int) -> Optional["CyncDevice"]:
        return self.get((home_id, dev_id))

    def in_home(self, home_id: int) -> List["CyncDevice"]:
        """The home's devices, sorted by mesh id."""
        return sorted((d for (h, _), d in self.items() if h == home_id), key=lambda d: d.id)

    def homes_with(self, dev_id: int) -> Set[int]:
        """Ids of every home that has a device with this mesh id."""
        return {h for (h, i) in self if i == dev_id}

    # ---- homes
    def home_ids(self) -> List[int]:
        """Sorted ids of the homes that have devices (a home without devices cannot have a bridge)."""
        return sorted({h for (h, _) in self})

    def home(self, home_id: int) -> Optional[HomeInfo]:
        return self._homes.get(home_id)

    def home_name(self, home_id: int) -> Optional[str]:
        info = self._homes.get(home_id)
        return info.name if info is not None else None

    def home_switch_ids(self, home_id: int) -> Dict[int, "CyncDevice"]:
        """switch_id -> device, for the home's devices that have a configured ``switch_id``."""
        return {d.switch_id: d for d in self.in_home(home_id) if d.switch_id is not None}

    def homes_for_bridge_ip(self, ip: str) -> Set[int]:
        """Homes (with devices) whose ``bridges:`` list contains this IP."""
        norm = normalize_ip(ip)
        if norm is None:
            return set()
        return {h for h in self.home_ids() if (info := self._homes.get(h)) and norm in info.bridges}

    def describe_home(self, home_id: int) -> str:
        name = self.home_name(home_id)
        return f"'{name}' ({home_id})" if name is not None else str(home_id)


# ---- pure resolution helpers
def parse_queue_id(raw: Optional[bytes]) -> Optional[int]:
    """The 0x23 hello queue id bytes as a big-endian int, None when empty."""
    if not raw:
        return None
    return int.from_bytes(bytes(raw), "big")


def homes_for_queue_id(registry: DeviceRegistry, queue_id: int) -> Dict[int, str]:
    """home_id -> why it matched, for every home that has a device whose switch_id equals queue_id."""
    out: Dict[int, str] = {}
    for h in registry.home_ids():
        dev = registry.home_switch_ids(h).get(queue_id)
        if dev is not None:
            out[h] = f"equals the switch_id of device '{dev.name}' ({dev.id}) in home {registry.describe_home(h)}"
    return out


def unresolved_bridge_message(
    registry: DeviceRegistry, queue_id: Optional[int], ip_address: Optional[str] = None
) -> str:
    """User-facing WARNING text for a bridge whose home could not be worked out."""
    homes = ", ".join(registry.describe_home(h) for h in registry.home_ids())
    qid = f"0x{queue_id:08x} ({queue_id})" if queue_id is not None else "none seen"
    who = f"bridge {ip_address}" if ip_address else "a bridge"
    return (
        f"Could not work out which Cync home {who} belongs to (homes: {homes}). Its 0x23 queue id is {qid}, which "
        f"matches no device switch_id in the config. Until this is resolved the bridge is not used for commands. "
        f"Fix: re-export the config from the cloud (the export writes each Wi-Fi device's switch_id, which "
        f"identifies the bridge from its first packet), then restart. If that does not help, add its IP to the "
        f"right home in cync_mesh.yaml, e.g. '{BRIDGES_KEY}: [\"{ip_address or '192.168.1.50'}\"]' under that "
        f"home (see docs/multi_home.md)."
    )


@dataclass(frozen=True)
class HomeMatch:
    """A resolved session home: which home, which signal decided it, and a human-readable reason."""

    home_id: int
    method: str
    detail: str


class HomeResolver:
    """
    Per-session home resolution. Signals are applied in a fixed priority: the first one that
    resolves wins and later signals are ignored. ``observe_queue_id``/``pin`` return a ``HomeMatch`` only on
    the call that newly resolved the home, else None, so the caller knows when to log.
    """

    def __init__(self, registry: DeviceRegistry, ip_address: Optional[str] = None):
        self.registry = registry
        self.ip_address = ip_address
        self.match: Optional[HomeMatch] = None
        self.queue_id: Optional[int] = None
        self.queue_id_detail: str = "no 0x23 queue id seen yet"
        homes = registry.home_ids()
        # a) exactly one home
        if len(homes) == 1:
            self.match = HomeMatch(homes[0], METHOD_SINGLE_HOME, "only one home is configured")
            return
        # b) manual 'bridges:' override
        if ip_address is not None:
            listed = registry.homes_for_bridge_ip(ip_address)
            if len(listed) == 1:
                h = next(iter(listed))
                self.match = HomeMatch(
                    h, METHOD_BRIDGES, f"{ip_address} is in the '{BRIDGES_KEY}:' list of home {registry.describe_home(h)}"
                )

    @property
    def resolved(self) -> bool:
        return self.match is not None

    @property
    def home_id(self) -> Optional[int]:
        return self.match.home_id if self.match is not None else None

    @property
    def method(self) -> Optional[str]:
        return self.match.method if self.match is not None else None

    @property
    def queue_id_hex(self) -> Optional[str]:
        return f"{self.queue_id:08x}" if self.queue_id is not None else None

    def _resolve(self, home_id: int, method: str, detail: str) -> Optional[HomeMatch]:
        if self.match is not None:
            return None
        self.match = HomeMatch(home_id, method, detail)
        return self.match

    # c) queue id
    def observe_queue_id(self, raw: Optional[bytes]) -> Optional[HomeMatch]:
        """Record the 0x23 queue id; resolves when it matches the switch_id of a device in exactly one home."""
        self.queue_id = parse_queue_id(raw)
        if self.queue_id is None:
            self.queue_id_detail = "the 0x23 queue id was empty"
            return None
        found = homes_for_queue_id(self.registry, self.queue_id)
        if not found:
            self.queue_id_detail = "matches no device switch_id"
        elif len(found) > 1:
            self.queue_id_detail = "is ambiguous, it " + "; ".join(found[h] for h in sorted(found))
        else:
            h, why = next(iter(found.items()))
            self.queue_id_detail = why
            if self.match is not None:
                self.queue_id_detail += f" (home already decided by {self.match.method})"
            return self._resolve(h, METHOD_QUEUE_ID, f"queue id {self.queue_id} {why}")
        return None

    def pin(self, home_id: int, method: str, detail: str) -> Optional[HomeMatch]:
        """Resolve from outside evidence (tests, tools). The live code resolves through the signals above."""
        if home_id not in self.registry.home_ids():
            raise ValueError(f"home {home_id} is not configured")
        return self._resolve(home_id, method, detail)


# ---- exporter helper
def _config_homes(cfg) -> Dict[str, dict]:
    if not isinstance(cfg, dict):
        return {}
    for key in CONFIG_MAIN_KEYS:
        homes = cfg.get(key)
        if isinstance(homes, dict):
            return homes
    return {}


def as_positive_int(value) -> Optional[int]:
    """
    The one rule for ids read from YAML or the cloud (home ``id``, ``switch_id``, cloud ``switchID``): a positive int,
    or a string of digits (a quoted number). None for anything else: 0, negatives, bools, floats, other text.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str) and value.strip().isdecimal():  # isdigit() also accepts e.g. "²", which int() rejects
        n = int(value.strip())
        return n if n > 0 else None
    return None


def as_home_id(value) -> Optional[int]:
    """A config home ``id`` (see ``as_positive_int``)."""
    return as_positive_int(value)


def carry_over_bridges(new_cfg: dict, old_cfg) -> int:
    """
    Copy each old home's ``bridges:`` list into the new export (matched by home id, so a renamed
    home keeps it). A value already present in the new config wins. Returns how many homes got one.
    Pure: mutates ``new_cfg`` in place, tolerates any junk in ``old_cfg``.
    """
    old_bridges: Dict[int, list] = {}
    for home_cfg in _config_homes(old_cfg).values():
        if not isinstance(home_cfg, dict) or BRIDGES_KEY not in home_cfg:
            continue
        home_id = as_home_id(home_cfg.get("id"))
        if home_id is not None:
            old_bridges[home_id] = home_cfg[BRIDGES_KEY]
    copied = 0
    for home_cfg in _config_homes(new_cfg).values():
        if not isinstance(home_cfg, dict) or BRIDGES_KEY in home_cfg:
            continue
        home_id = as_home_id(home_cfg.get("id"))
        if home_id in old_bridges:
            home_cfg[BRIDGES_KEY] = old_bridges[home_id]
            copied += 1
    return copied
