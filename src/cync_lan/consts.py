"""Legacy constants converted from original JS code. Older firmware devices"""

ITER: int = 0
# Some commands require a response that iterates a specific byte
# It appears it can be shared across all devices, but it should still
# be iterated
CLIENT_ITER_REQUEST: bytes = bytearray([0x83])


def server_iter_response():
    global ITER
    ITER += 1
    return bytearray([0x88, 0x00, 0x00, 0x00, 0x03, 0x00, ITER % 0xFF, 0x00])


# The client sends along some sort of identifier in its first request
# We don't care but it likes a response
CLIENT_INFO_BUFFER = 0x23
SERVER_CLIENT_ACK = bytes(
    [
        0x28,
        0x00,
        0x00,
        0x00,
        0x02,
        0x00,
        0x00,
    ]
)

# There is a specific handshake that needs to occur before the client
# will accept commands
CLIENT_CONNECTION_REQUEST = bytearray(
    [
        0xC3,
        0x00,
        0x00,
        0x00,
        0x01,
        0x0C,
    ]
)
SERVER_CONNECTION_RESPONSE = bytearray(
    [
        0xC8,
        0x00,
        0x00,
        0x00,
        0x0B,
        0x0D,
        0x07,
        0xE6,
        0x02,
        0x13,
        0x07,
        0x0A,
        0x14,
        0x29,
        0xFD,
        0xA8,
    ]
)

# The client will sometimes send diagnostic data - acknowledge it
CLIENT_DATA = bytearray([0x43, 0x00, 0x00, 0x00])

# This ack is used for several things
SERVER_CLIENT_DATA_ACK = bytearray(
    [
        0x48,
        0x00,
        0x00,
        0x00,
        0x03,
        0x01,
        0x01,
        0x00,
    ]
)


# Clients get fussy if they don't hear from the server frequently
CLIENT_HEARTBEAT = bytearray([0xD3, 0x00, 0x00, 0x00, 0x00])
SERVER_HEARTBEAT = bytearray([0xD8, 0x00, 0x00, 0x00, 0x00])

CMD_TURN_ON = bytearray(
    [
        0x73,
        0x00,
        0x00,
        0x00,
        0x1F,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x7E,
        0x00,
        0x00,
        0x00,
        0x00,
        0xF8,
        0xD0,
        0x0D,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0xD0,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
    ]
)
CMD_TURN_OFF = bytearray(
    [
        0x73,
        0x00,
        0x00,
        0x00,
        0x1F,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x7E,
        0x00,
        0x00,
        0x00,
        0x00,
        0xF8,
        0xD0,
        0x0D,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0xD0,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ]
)

# Some commands have a "return" code that we can use to make sure
# the state of devices stays in sync
CLIENT_STATUS_ON = bytearray([0x7B, 0x00, 0x00, 0x00, 0x07, 0x01])
CLIENT_STATUS_OFF = bytearray([0x7B, 0x00, 0x00, 0x00, 0x07, 0x00])

CLIENT_STATUS_BRIGHTNESS = bytearray(
    [
        0x7B,
        0x00,
        0x00,
        0x00,
        0x07,
        0x02,
    ]
)

CLIENT_STATUS_TEMPERATURE = bytearray(
    [
        0x7B,
        0x00,
        0x00,
        0x00,
        0x07,
        0x03,
    ]
)

def cmd_set_brightness(brightness: Union[int, str, bytes]):
    return bytearray(
        [
            0x73,
            0x00,
            0x00,
            0x00,
            0x1D,
            0x02,
            brightness,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x7E,
            0x00,
            0x00,
            0x00,
            0x00,
            0xF8,
            0xD2,
            0x0B,
            0x00,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0xD2,
            0x00,
            0x00,
            brightness,
            0x00,
            0x00,
        ]
    )


def cmd_set_color_temperature(temperature):
    return bytearray(
        [
            0x73,
            0x00,
            0x00,
            0x00,
            0x1E,
            0x03,
            temperature,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x7E,
            0x00,
            0x00,
            0x00,
            0x00,
            0xF8,
            0xE2,
            0x0C,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0xE2,
            0x00,
            0x00,
            0x05,
            temperature,
            0x00,
            0x00,
        ]
    )


def cmd_set_color(R, G, B):
    return bytearray(
        [
            0x73,
            0x00,
            0x00,
            0x00,
            0x20,
            0x04,
            R,
            G,
            B,
            0x00,
            0x00,
            0x7E,
            0x00,
            0x00,
            0x00,
            0x00,
            0xF8,
            0xE2,
            0x0E,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0xE2,
            0x00,
            0x00,
            0x04,
            R,
            G,
            B,
            0x00,
            0x00,
        ]
    )

