import ast
import dataclasses
from pathlib import Path

from cync_lan.metadata import model_info as mi

SRC = Path(mi.__file__)


def _fields(cls):
    return {f.name for f in dataclasses.fields(cls)} | {
        # pydantic alias
        "color",
    }


def test_no_constructor_kwarg_is_silently_dropped():
    """pydantic dataclasses ignore unknown kwargs, so a typo like model_info= vanishes without an error."""
    classes = {n: getattr(mi, n) for n in (
        "DeviceTypeInfo", "LightCapabilities", "SwitchCapabilities", "LightCharacteristics",
        "DeviceProtocol", "OpcodeFamily",
    )}
    bad = []
    for node in ast.walk(ast.parse(SRC.read_text())):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) in classes:
            allowed = _fields(classes[node.func.id])
            bad += [(node.func.id, k.arg, node.lineno) for k in node.keywords if k.arg and k.arg not in allowed]
    assert not bad, bad


def test_type_155_has_dynamic_effects():
    assert mi.device_type_map[155].capabilities.dynamic is True


def test_switches_stay_dimmable():
    assert mi.SwitchCapabilities().dimmable is True


def test_model_string_includes_cri_without_other_details():
    info = mi.DeviceTypeInfo(
        type=mi.DeviceClassification.LIGHT, model_name="X",
        characteristics=mi.LightCharacteristics(cri=90),
    )
    assert info.model_string == "X [90 CRI]"


def test_model_string_full():
    info = mi.device_type_map[169]
    assert info.model_string == (
        "Reveal HD+ Full Color 4 Inch Wafer Downlight [CFIXCNLR4CRVD 760 lum 2000-7000K 90 CRI 14W]"
    )


def test_model_string_plain():
    assert mi.DeviceTypeInfo(model_name="Plain").model_string == "Plain"


def test_type_127_eave_lights():
    """GE Cync Dynamic Effects Outdoor Smart Eave Lights (CEV100CDOD), fw 1.0.510."""
    info = mi.device_type_map[127]
    assert info.capabilities.color and info.capabilities.tunable_white and info.capabilities.dynamic


def test_type_171_full_color_a19_matter():
    """GE CYNC Full Color A19, Matter-capable revision (CLEDA199CD1MS), fw 1.1.204."""
    info = mi.device_type_map[171]
    assert info.capabilities.color and info.capabilities.tunable_white and info.protocol.MATTER
