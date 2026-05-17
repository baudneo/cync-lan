from enum import StrEnum
from typing import Annotated, List, Optional, Union

from pydantic import Field
from pydantic.dataclasses import dataclass

MULTI_ENDPOINT_TYPES = [67]


class DeviceClassification(StrEnum):
    LIGHT = "light"
    SWITCH = "switch"
    THERMOSTAT = "thermostat"
    BRIDGE = "bridge"
    UNKNOWN = "unknown"


@dataclass
class LightCapabilities:
    power: bool = True
    dimmable: bool = True
    tunable_white: bool = False
    dynamic: bool = False
    color: bool = False
    colour: Annotated[bool, Field(alias="color")] = False


@dataclass
class SwitchCapabilities(LightCapabilities):
    dimmable = False
    fan: bool = False
    plug: bool = False


@dataclass
class DeviceProtocol:
    BTLE: bool = True
    TCP: bool = False
    MATTER: bool = False


@dataclass
class OpcodeFamily:
    """Identifies which binary opcode family a device uses for control commands.

    Older GE/C-by-GE XLink Wi-Fi-direct devices (e.g. C by GE Sol, type 80) use a
    different opcode set for brightness (0xD2) and CCT (0xE2) than the newer Cync mesh
    devices which use 0xF0 for both.  All other fields on DeviceTypeInfo are transport or
    aesthetic; this one drives the binary packet structure.
    """

    sol_lamp: bool = False


@dataclass
class LightCharacteristics:
    min_kelvin: Optional[Annotated[int, Field(ge=2000, le=7000)]] = None
    max_kelvin: Optional[Annotated[int, Field(ge=2000, le=7000)]] = None
    lumens: Optional[Annotated[int, Field(ge=10)]] = None
    cri: Optional[Annotated[int, Field(ge=5, le=100)]] = None


@dataclass
class DeviceTypeInfo:
    type: DeviceClassification = Field(default=DeviceClassification.UNKNOWN)
    model_name: Optional[str] = "Unknown Device, See repo issue tracker"
    model_id: Optional[str] = None
    protocol: DeviceProtocol = Field(default_factory=DeviceProtocol)
    opcodes: OpcodeFamily = Field(default_factory=OpcodeFamily)
    capabilities: Union[LightCapabilities, SwitchCapabilities, None] = None
    characteristics: Optional[LightCharacteristics] = None
    supported: bool = Field(
        default=True, description="Whether this device type is supported"
    )
    notes: Optional[List[str]] = None

    @property
    def model_string(self) -> str:
        """Return a string representation of the model name, ID and characteristics."""
        base_str = self.model_name
        add_str = ""
        if self.model_id:
            add_str = self.model_id
        if self.type == DeviceClassification.LIGHT:
            if self.characteristics:
                if self.characteristics.lumens:
                    if add_str:
                        add_str += " "
                    add_str += f"{self.characteristics.lumens} lum"
                if self.characteristics.min_kelvin:
                    if (
                        self.characteristics.min_kelvin
                        and self.characteristics.max_kelvin
                    ):
                        if (
                            self.characteristics.min_kelvin
                            != self.characteristics.max_kelvin
                        ):
                            kelvin_data = f"{self.characteristics.min_kelvin}-{self.characteristics.max_kelvin}K"
                        else:
                            kelvin_data = f"{self.characteristics.min_kelvin}K"
                    else:
                        kelvin_data = f"{self.characteristics.min_kelvin}K"
                    if add_str:
                        add_str += " "
                    add_str += f"{kelvin_data}"
                if self.characteristics.cri:
                    if add_str:
                        add_str += " "
                        add_str += f"{self.characteristics.cri} CRI"
        if add_str:
            add_str = f" [{add_str}]"
        return base_str + add_str


"""Maps a device type ID to its corresponding DeviceTypeInfo."""
device_type_map = {
    5: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Tunable White A19 Bulb",
        model_id=None,
        characteristics=LightCharacteristics(lumens=800),
        capabilities=LightCapabilities(tunable_white=True),
    ),
    6: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Light (Unknown)",
        model_id=None,
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    7: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Light (Unknown)",
        model_id=None,
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    8: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Light (Unknown)",
        model_id=None,
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    9: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Soft White A19 Bulb",
        model_id=None,
        capabilities=LightCapabilities(),
        characteristics=LightCharacteristics(lumens=800, min_kelvin=2700),
    ),
    10: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Tunable White Light (Unknown)",
        model_id=None,
        capabilities=LightCapabilities(tunable_white=True),
    ),
    11: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Tunable White Light (Unknown)",
        model_id=None,
        capabilities=LightCapabilities(tunable_white=True),
    ),
    14: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Tunable White Light (Unknown)",
        model_id=None,
        capabilities=LightCapabilities(tunable_white=True),
    ),
    15: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Tunable White Light (Unknown)",
        model_id=None,
        capabilities=LightCapabilities(tunable_white=True),
    ),
    17: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="White Dimmable A19 Bulb (BTLE only)",
        model_id="CLED199L2",
        capabilities=LightCapabilities(),
        characteristics=LightCharacteristics(min_kelvin=2700, lumens=760),
    ),
    18: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="White Dimmable A19 Bulb (BTLE only)",
        model_id="CLED199L2",
        capabilities=LightCapabilities(),
        characteristics=LightCharacteristics(min_kelvin=2700, lumens=760),
    ),
    19: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        protocol=DeviceProtocol(TCP=True),
        model_name="Tunable White A19 Bulb",
        capabilities=LightCapabilities(tunable_white=True),
    ),
    20: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Tunable White Light (Unknown)",
        protocol=DeviceProtocol(TCP=True),
        model_id=None,
        capabilities=LightCapabilities(tunable_white=True),
    ),
    21: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="C by GE Full Color A19 Bulb (BTLE only)",
        model_id="CLEDA1911C2",
        characteristics=LightCharacteristics(lumens=760),
        capabilities=LightCapabilities(color=True, tunable_white=True),
    ),
    22: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="C by GE Full Color BR30 Bulb (BTLE only)",
        model_id="CLEDR3010C2",
        characteristics=LightCharacteristics(lumens=700),
        capabilities=LightCapabilities(color=True, tunable_white=True),
    ),
    23: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Light (Unknown)",
        capabilities=LightCapabilities(color=True, tunable_white=True),
    ),
    25: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Tunable White Light (Unknown)",
        model_id=None,
        capabilities=LightCapabilities(tunable_white=True),
    ),
    26: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="C by GE Tunable White BR30 Bulb (BTLE only)",
        model_id="CLEDR309S2",
        characteristics=LightCharacteristics(
            lumens=800, min_kelvin=2000, max_kelvin=7000
        ),
        capabilities=LightCapabilities(tunable_white=True),
    ),
    28: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Tunable White Light (Unknown)",
        model_id=None,
        capabilities=LightCapabilities(tunable_white=True),
    ),
    29: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Tunable White Light (Unknown)",
        model_id=None,
        capabilities=LightCapabilities(tunable_white=True),
    ),
    30: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="C by GE Full Color A19 Bulb (BTLE only)",
        model_id="CLEDA1911C2",
        characteristics=LightCharacteristics(lumens=760),
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(color=True, tunable_white=True),
    ),
    31: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="C by GE Full Color A19 Bulb (BTLE only)",
        model_id="CLEDA1911C2",
        characteristics=LightCharacteristics(lumens=800),
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(color=True, tunable_white=True),
    ),
    32: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Light (Unknown)",
        capabilities=LightCapabilities(color=True, tunable_white=True),
    ),
    33: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Light (Unknown)",
        capabilities=LightCapabilities(color=True, tunable_white=True),
    ),
    34: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Light (Unknown)",
        capabilities=LightCapabilities(color=True, tunable_white=True),
    ),
    35: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Light (Unknown)",
        capabilities=LightCapabilities(color=True, tunable_white=True),
    ),
    37: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Dimmer Switch with Motion and Ambient Light",
        model_id="CSWDMOCBWF1",
        protocol=DeviceProtocol(TCP=True),
        capabilities=SwitchCapabilities(dimmable=True, color=True, tunable_white=True),
    ),
    39: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Paddle Switch",
        model_id=" CSWONBLPWF1",
        protocol=DeviceProtocol(TCP=True),
        capabilities=SwitchCapabilities(dimmable=True, color=True, tunable_white=True),
    ),
    40: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Paddle Switch",
        model_id="CSWONBLTWF1",
        protocol=DeviceProtocol(TCP=True),
        capabilities=SwitchCapabilities(dimmable=True, color=True, tunable_white=True),
    ),
    41: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Reveal HD+ Full Color Under Cabinet Light - 12 Inch",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(color=True, tunable_white=True),
        characteristics=LightCharacteristics(lumens=750),
    ),
    42: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Reveal HD+ Full Color Under Cabinet Light - 18 Inch",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(color=True, tunable_white=True),
        characteristics=LightCharacteristics(lumens=1150),
    ),
    43: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Reveal HD+ Full Color Under Cabinet Light - 24 Inch",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(color=True, tunable_white=True),
        characteristics=LightCharacteristics(lumens=1500),
    ),
    47: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name='Reveal Full Color 6" Recessed Downlight',
        model_info="CFIXRSCR6CRVD",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(color=True, tunable_white=True),
    ),
    48: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="C by GE (C Start Smart) Paddle Switch",
        model_id="CSWDMBLBWF1",
        protocol=DeviceProtocol(TCP=True),
        capabilities=SwitchCapabilities(dimmable=True, color=True, tunable_white=True),
    ),
    49: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="C by GE (C Start Smart) Dimmer Switch with Motion and Ambient Light",
        model_id="CSWDMOCBWF1",
        protocol=DeviceProtocol(TCP=True),
        capabilities=SwitchCapabilities(dimmable=True, color=True, tunable_white=True),
    ),
    51: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Switch",
        model_id=None,
        protocol=DeviceProtocol(TCP=True),
        capabilities=SwitchCapabilities(dimmable=True, color=True, tunable_white=True),
    ),
    52: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Switch",
        protocol=DeviceProtocol(TCP=True),
        capabilities=SwitchCapabilities(dimmable=True, color=True, tunable_white=True),
    ),
    53: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Toggle Switch",
        protocol=DeviceProtocol(TCP=True),
        capabilities=SwitchCapabilities(dimmable=True, color=True, tunable_white=True),
    ),
    55: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Dimmer Switch - No Neutral",
        protocol=DeviceProtocol(TCP=True),
        capabilities=SwitchCapabilities(dimmable=True, color=True, tunable_white=True),
    ),
    56: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Dimmable Motion Light Switch",
        protocol=DeviceProtocol(TCP=True),
        capabilities=SwitchCapabilities(dimmable=True, color=True, tunable_white=True),
    ),
    57: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Paddle Switch - No Neutral",
        model_id="CSWONBLPWF1NN",
        protocol=DeviceProtocol(TCP=True),
        capabilities=SwitchCapabilities(dimmable=True, color=True, tunable_white=True),
    ),
    58: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Switch - No Neutral",
        protocol=DeviceProtocol(TCP=True),
        capabilities=SwitchCapabilities(dimmable=True, color=True, tunable_white=True),
    ),
    59: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Switch",
        protocol=DeviceProtocol(TCP=True),
        capabilities=SwitchCapabilities(dimmable=True, color=True, tunable_white=True),
    ),
    64: DeviceTypeInfo(
        type=DeviceClassification.SWITCH,
        model_name="Indoor Plug",
        protocol=DeviceProtocol(TCP=True),
        capabilities=SwitchCapabilities(plug=True),
    ),
    65: DeviceTypeInfo(
        type=DeviceClassification.SWITCH,
        model_name="Indoor Plug (Unknown)",
        protocol=DeviceProtocol(TCP=True),
        capabilities=SwitchCapabilities(plug=True),
    ),
    66: DeviceTypeInfo(
        type=DeviceClassification.SWITCH,
        model_name="Indoor Plug (Unknown)",
        protocol=DeviceProtocol(TCP=True),
        capabilities=SwitchCapabilities(plug=True),
    ),
    67: DeviceTypeInfo(
        type=DeviceClassification.SWITCH,
        model_name="Outdoor Plug - Dual Outlet",
        model_id="CPLGOD2BLG1",
        protocol=DeviceProtocol(TCP=True, MATTER=True),
        capabilities=SwitchCapabilities(plug=True),
        notes=[
            "when reading the 0x83 internal state, bri byte is the bitmask, use -> & (1 << (sub_id - 1))",
            "temp can sometimes be 255, unknown what it means",
            "power byte is 1 if either outlet on, 0 if either off",
            "sending a command is easy, has a dedicated byte for sub-id directly after the device-id byte",
        ],
    ),
    68: DeviceTypeInfo(
        type=DeviceClassification.SWITCH,
        model_name="Indoor Plug",
        protocol=DeviceProtocol(TCP=True),
        capabilities=SwitchCapabilities(plug=True),
    ),
    71: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Dynamic Effects Premium Thin Light Strip",
        model_info="CSTR16CDID",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    72: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Dynamic Effects Premium Light Strip",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True),
        characteristics=LightCharacteristics(
            lumens=1600, min_kelvin=2000, max_kelvin=7000, cri=80
        ),
    ),
    76: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Dynamic Effects Cafe` Lights",
        model_info="CCF48CDOD",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True, dynamic=True),
        characteristics=LightCharacteristics(
            lumens=130, min_kelvin=2000, max_kelvin=7000
        ),
    ),
    80: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="C by GE Sol / XLink Tunable White",
        protocol=DeviceProtocol(TCP=True),
        opcodes=OpcodeFamily(sol_lamp=True),
        capabilities=LightCapabilities(tunable_white=True),
    ),
    81: DeviceTypeInfo(
        type=DeviceClassification.SWITCH,
        model_name="Fan Controller",
        model_id="CSWFSBLBWF1/ST-1P",
        protocol=DeviceProtocol(TCP=True),
        capabilities=SwitchCapabilities(fan=True),
    ),
    82: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Tunable White Light (Unknown)",
        capabilities=LightCapabilities(tunable_white=True),
    ),
    83: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Tunable White Light (Unknown)",
        capabilities=LightCapabilities(tunable_white=True),
    ),
    85: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Tunable White Light (Unknown)",
        capabilities=LightCapabilities(tunable_white=True),
    ),
    107: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Reveal HD+ Bulb",
        model_info="CLEDA199CDRV",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    113: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Wire-Free Dimmer with White Temperature Switch (BTLE only)",
        capabilities=SwitchCapabilities(dimmable=True, color=True, tunable_white=True),
        supported=False,
    ),
    125: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Dimmer Switch",
        model_id="CSWDMBLBWF1",
        protocol=DeviceProtocol(TCP=True, MATTER=True),
        capabilities=LightCapabilities(color=True, tunable_white=True),
    ),
    # 125: DeviceTypeInfo(
    #     type=DeviceClassification.SWITCH,
    #     model_name="Paddle Switch",
    #     model_id="CSWDMBLBWF1",
    #     protocol=DeviceProtocol(TCP=True, MATTER=True),
    #     capabilities=SwitchCapabilities(dimmable=True, color=True, tunable_white=True),
    # ),
    128: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Dimmable A19 Bulb",
        model_id="CLEDA199LD1",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(),
        characteristics=LightCharacteristics(lumens=800, cri=90, min_kelvin=2700),
    ),
    129: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Tunable White Light (Unknown)",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True),
    ),
    130: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Tunable White Light (Unknown)",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True),
    ),
    131: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color A19 Bulb",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    132: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Light (Unknown)",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    133: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color LED Light Strip Controller",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    135: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Tunable White Light (Unknown)",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True),
    ),
    136: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Tunable White Light (Unknown)",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True),
    ),
    137: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color A19 Bulb",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    138: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color BR30 Floodlight",
        characteristics=LightCharacteristics(
            lumens=750, min_kelvin=2000, max_kelvin=7000, cri=90
        ),
        model_id="CLEDR309CD1",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    139: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Light (Unknown)",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    140: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Outdoor PAR38 Floodlight",
        characteristics=LightCharacteristics(lumens=1300),
        model_id="CLEDP3815CD1",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    141: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Light (Unknown)",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    142: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Light (Unknown)",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    143: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Light (Unknown)",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    144: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Tunable White Light (Unknown)",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True),
    ),
    145: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Tunable White Light (Unknown)",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True),
    ),
    146: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Edison ST19 Bulb",
        characteristics=LightCharacteristics(lumens=500),
        model_id="CLEDST196CDGS",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    147: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Edison G25 Bulb",
        characteristics=LightCharacteristics(lumens=500),
        model_id="CLEDG256CDGS",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    148: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="White Edison ST19 Bulb",
        protocol=DeviceProtocol(TCP=True),
        characteristics=LightCharacteristics(min_kelvin=2700),
        capabilities=LightCapabilities(),
    ),
    151: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Soft White Decorative Candle Light",
        model_id="CLEDBM6LDGF",
        protocol=DeviceProtocol(TCP=True),
        characteristics=LightCharacteristics(lumens=500, min_kelvin=2700, cri=90),
        capabilities=LightCapabilities(),
    ),
    152: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Reveal HD+ White A19 Bulb",
        protocol=DeviceProtocol(TCP=True),
        characteristics=LightCharacteristics(min_kelvin=2700),
        capabilities=LightCapabilities(),
    ),
    153: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Light (Unknown)",
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    154: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        protocol=DeviceProtocol(TCP=True),
        model_name="Full Color Light (Unknown)",
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    155: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Dynamic Effects E26 Bulb",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(dimmable=True, color=True, tunable_white=True),
        characteristics=LightCharacteristics(dynamic=True),
    ),
    156: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        protocol=DeviceProtocol(TCP=True),
        model_name="Full Color Light (Unknown)",
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    158: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Light (Unknown)",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    159: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Light (Unknown)",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    160: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Light (Unknown)",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    161: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Light (Unknown)",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    162: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Light (Unknown)",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    163: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Light (Unknown)",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    164: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        protocol=DeviceProtocol(TCP=True),
        model_name="Full Color Light (Unknown)",
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    165: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name="Full Color Light (Unknown)",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    169: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        characteristics=LightCharacteristics(lumens=760),
        model_id="CFIXCNLR4CRVD",
        model_name="Reveal HD+ Full Color 4 Inch Wafer Downlight",
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(tunable_white=True, color=True),
    ),
    170: DeviceTypeInfo(
        type=DeviceClassification.LIGHT,
        model_name='4" Wafer Light',
        protocol=DeviceProtocol(TCP=True),
        capabilities=LightCapabilities(dimmable=True, color=True, tunable_white=True),
    ),
    224: DeviceTypeInfo(
        type=DeviceClassification.THERMOSTAT,
        model_name="Thermostat",
        protocol=DeviceProtocol(TCP=True),
    ),
}
