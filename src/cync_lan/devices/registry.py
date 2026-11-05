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
     the cloud export). It is also compared with each home's ``id``: that was the other early guess, it was
     never seen to match and is kept only in case some firmware does it;
  d) a fingerprint of the mesh ids the bridge reports in its mesh-info replies (see ``home_fits`` /
     ``plausible_homes``; 0x83 status ids are not used, they can carry group/room ids). A home
     "fits" when it has every reported id (and, when both are known, the bridge's device type). A fitting
     home rules out another home only when that other home lacks MORE reported ids than the fitting home
     has configured ids the bridge never reported. Resolved when exactly one home is left and it fits.
     A single id is never proof on its own: a device added after the last export shows up as an id the
     bridge's real home does not have in the config, and with nested ids (1..N in every home) that id
     usually exists in a bigger home. A missing id never selects a home (devices can be offline); it can
     only stop a decision. An id no home knows is ignored.

Everything here is pure: no ``g``, no I/O, no logging inside the resolver. Callers log.
"""

import ipaddress
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from cync_lan.devices.device import CyncDevice
    from cync_lan.devices.group import CyncGroup

__all__ = [
    "BRIDGES_KEY",
    "GROUPS_KEY",
    "SWITCH_ID_KEY",
    "DeviceKey",
    "DeviceRegistry",
    "HomeInfo",
    "HomeMatch",
    "HomeResolver",
    "ambiguity_message",
    "as_home_id",
    "as_positive_int",
    "carry_over_bridges",
    "homes_for_queue_id",
    "HomeFit",
    "format_ids",
    "home_fits",
    "plausible_homes",
    "normalize_ip",
    "parse_queue_id",
]

BRIDGES_KEY = "bridges"
"""Optional per-home config key: list of bridge IP strings (manual home override)."""
GROUPS_KEY = "groups"
"""Optional per-home config key: Cync rooms, ``{group_id: {name, members: [dev_id, ...], subgroup}}`` (cloud export)."""
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
METHOD_FINGERPRINT = "fingerprint"


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
        # Cync rooms / sub-rooms, keyed by (home_id, group_id); kept apart so .values() stays "every device"
        self._groups: Dict[Tuple[int, int], "CyncGroup"] = {}

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

    def add_group(self, group: "CyncGroup") -> "CyncGroup":
        """Add a group after its home's devices: resolves ``group.members`` to the devices that exist (others dropped)."""
        group.members = [d for d in (self.get_device(group.home_id, m) for m in group.member_ids) if d is not None]
        self._groups[group.key] = group
        return group

    # ---- groups
    def get_group(self, home_id: Optional[int], group_id: int) -> Optional["CyncGroup"]:
        return self._groups.get((home_id, group_id))

    def groups(self) -> List["CyncGroup"]:
        return sorted(self._groups.values(), key=lambda gr: gr.key)

    def groups_with(self, device: "CyncDevice") -> List["CyncGroup"]:
        """The groups this device is a member of."""
        return [gr for gr in self._groups.values() if device in gr.members]

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
    """home_id -> why it matched, for every home whose id or one of whose device switch_ids equals queue_id."""
    out: Dict[int, str] = {}
    for h in registry.home_ids():
        if h == queue_id:
            out[h] = f"equals the id of home {registry.describe_home(h)}"
            continue
        dev = registry.home_switch_ids(h).get(queue_id)
        if dev is not None:
            out[h] = f"equals the switch_id of device '{dev.name}' ({dev.id}) in home {registry.describe_home(h)}"
    return out


def format_ids(ids: Iterable[int]) -> str:
    """Sorted ids with runs collapsed: [1, 2, 3, 5, 7, 8] -> '1-3, 5, 7-8'."""
    out: List[str] = []
    run: List[int] = []
    for i in sorted(set(ids)):
        if run and i == run[-1] + 1:
            run.append(i)
            continue
        if run:
            out.append(f"{run[0]}-{run[-1]}" if len(run) > 1 else str(run[0]))
        run = [i]
    if run:
        out.append(f"{run[0]}-{run[-1]}" if len(run) > 1 else str(run[0]))
    return ", ".join(out) if out else "none"


@dataclass(frozen=True)
class HomeFit:
    """How well one home explains the ids a bridge reported."""

    home_id: int
    lacking: FrozenSet[int]
    """Reported ids this home does not have in the config."""
    type_mismatch: bool
    """The bridge's own id has a known, different device type in this home."""
    unreported: int
    """How many of this home's configured ids the bridge did not report (offline, or not this home)."""

    @property
    def missing(self) -> int:
        """Evidence against this home: reported ids it lacks, plus one for a type mismatch."""
        return len(self.lacking) + int(self.type_mismatch)

    @property
    def fits(self) -> bool:
        return self.missing == 0

    def describe_against(self) -> str:
        parts = []
        if self.lacking:
            parts.append(f"lacks reported id(s) {format_ids(self.lacking)}")
        if self.type_mismatch:
            parts.append("has a different type for the bridge's id")
        return " and ".join(parts) or "fits"


def home_fits(
    registry: DeviceRegistry,
    reported: Iterable[int],
    bridge: Optional[Tuple[int, Optional[int]]] = None,
) -> Dict[int, HomeFit]:
    """
    home_id -> HomeFit for every home with devices. ``reported``: every id the bridge reported (ids no home knows are
    ignored). ``bridge``: (its own id, its device type or None). The type counts only when the bridge reported one, the
    home's device has a known type, and at least one home has that type at that id (else the type byte is not
    comparable and is ignored).
    """
    home_ids: Dict[int, Set[int]] = {}
    for h, i in registry:
        home_ids.setdefault(h, set()).add(i)
    known = set().union(*home_ids.values()) if home_ids else set()
    seen = {i for i in reported if i in known}
    bridge_id, bridge_type = bridge if bridge is not None else (None, None)
    if bridge_id is not None and bridge_id in known:
        seen.add(bridge_id)
    use_type = bool(bridge_type) and any(
        (d := registry.get_device(h, bridge_id)) is not None and d.type == bridge_type for h in home_ids
    )
    out: Dict[int, HomeFit] = {}
    for h, ids in home_ids.items():
        mismatch = False
        if use_type:
            d = registry.get_device(h, bridge_id)
            mismatch = d is not None and d.type is not None and d.type != bridge_type
        out[h] = HomeFit(h, frozenset(seen - ids), mismatch, len(ids - seen))
    return out


def plausible_homes(fits: Dict[int, HomeFit]) -> FrozenSet[int]:
    """
    The homes the bridge may still be in. A home that fits (has every reported id) rules out another home only when
    that other home lacks more reported ids than the fitting home has unreported ids: otherwise "the other home's
    config is stale (devices added after the export)" explains the evidence as well as "some of the fitting home's
    devices are offline". When no home fits, nothing can be ruled out.
    """
    fitting = [f for f in fits.values() if f.fits]
    if not fitting:
        return frozenset(fits)
    return frozenset(
        h for h, f in fits.items() if not any(w.home_id != h and f.missing > w.unreported for w in fitting)
    )


def ambiguity_message(
    registry: DeviceRegistry,
    candidates: Iterable[int],
    queue_id: Optional[int],
    ip_address: Optional[str] = None,
    none_fit: bool = False,
) -> str:
    """
    User-facing WARNING text for a bridge whose home could not be worked out. ``none_fit``: no home has every id the
    bridge reported (the config is probably older than the account), as opposed to several homes having them all.
    """
    homes = ", ".join(registry.describe_home(h) for h in sorted(candidates))
    qid = f"0x{queue_id:08x} ({queue_id})" if queue_id is not None else "none seen"
    who = f"bridge {ip_address}" if ip_address else "a bridge"
    if none_fit:
        why = f"no single home in the config has every device id it reports (possible homes: {homes})"
    else:
        why = f"the device ids it reports fit several homes: {homes}"
    return (
        f"Could not work out which Cync home {who} belongs to: {why}. Its 0x23 queue id is {qid}, which matches "
        f"no device switch_id in the config. Until this is resolved the bridge is not used for commands. "
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
    resolves wins and later signals are ignored. ``observe_*``/``pin`` return a ``HomeMatch`` only on
    the call that newly resolved the home, else None, so the caller knows when to log and to flush
    anything it buffered.
    """

    def __init__(self, registry: DeviceRegistry, ip_address: Optional[str] = None):
        self.registry = registry
        self.ip_address = ip_address
        self.match: Optional[HomeMatch] = None
        # fingerprint candidates; None until an id was reported (= no evidence yet, every home possible)
        self.candidates: Optional[FrozenSet[int]] = None
        self.fits: Dict[int, HomeFit] = {}
        # every id the bridge reported this connection, and its own record (id, type)
        self._reported: Set[int] = set()
        self._bridge: Optional[Tuple[int, Optional[int]]] = None
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
        """Record the 0x23 queue id; resolves when it matches exactly one home (id or device switch_id)."""
        self.queue_id = parse_queue_id(raw)
        if self.queue_id is None:
            self.queue_id_detail = "the 0x23 queue id was empty"
            return None
        found = homes_for_queue_id(self.registry, self.queue_id)
        if not found:
            self.queue_id_detail = "matches no home id and no device switch_id"
        elif len(found) > 1:
            self.queue_id_detail = "is ambiguous, it " + "; ".join(found[h] for h in sorted(found))
        else:
            h, why = next(iter(found.items()))
            self.queue_id_detail = why
            if self.match is not None:
                self.queue_id_detail += f" (home already decided by {self.match.method})"
            return self._resolve(h, METHOD_QUEUE_ID, f"queue id {self.queue_id} {why}")
        return None

    # d) fingerprint
    def _fingerprint(self) -> Optional[HomeMatch]:
        """Re-score every home from all evidence so far; resolve when one home is left and it fits."""
        self.fits = home_fits(self.registry, self._reported, self._bridge)
        self.candidates = plausible_homes(self.fits)
        if len(self.candidates) != 1:
            return None
        h = next(iter(self.candidates))
        best = self.fits[h]
        if not best.fits:
            return None
        n = len(self.registry.in_home(h)) - best.unreported  # the fitting home has every reported (known) id
        others = "; ".join(
            f"{self.registry.describe_home(o)} {self.fits[o].describe_against()}"
            for o in sorted(self.fits) if o != h
        )
        bridge = ""
        if self._bridge is not None:
            bridge = f" (bridge id {self._bridge[0]}, type {self._bridge[1] or 'unknown'})"
        detail = (
            f"all {n} reported id(s){bridge} are in home {self.registry.describe_home(h)}, which has "
            f"{best.unreported} configured id(s) that were not reported; ruled out: {others or 'no other home'}"
        )
        return self._resolve(h, METHOD_FINGERPRINT, detail)

    def observe_bridge(self, dev_id: int, dev_type: Optional[int] = None) -> Optional[HomeMatch]:
        """
        The bridge's own record (first mesh-info record): its id counts as reported, and its device type (0/None =
        unknown) counts against a home only where that home's configured type is known and different.
        """
        if self.match is not None:
            return None
        self._bridge = (dev_id, dev_type or None)
        self._reported.add(dev_id)
        return self._fingerprint()

    def observe_ids(self, dev_ids: Iterable[int]) -> Optional[HomeMatch]:
        """
        Ids the bridge listed in a mesh-info reply. Evidence accumulates and is never removed, so only pass ids that
        describe the bridge's own mesh: not 0x83 status ids, which can be group/room ids.
        """
        if self.match is not None:
            return None
        self._reported.update(dev_ids)
        return self._fingerprint()

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
