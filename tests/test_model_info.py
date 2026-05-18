from cync_lan.metadata.model_info import device_type_map


def test_model_id_aliases_are_populated() -> None:
    assert device_type_map[47].model_id == "CFIXRSCR6CRVD"
    assert device_type_map[71].model_id == "CSTR16CDID"
    assert device_type_map[76].model_id == "CCF48CDOD"
    assert device_type_map[107].model_id == "CLEDA199CDRV"


def test_dynamic_effects_capability_for_type_155() -> None:
    assert device_type_map[155].capabilities.dynamic is True
