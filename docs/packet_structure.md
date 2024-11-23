There are a few components that make up a complete packet. There are request and response packets.

# Basic structure
The header is always present. The endpoint and queue ID are present in most packets. 
The data is present in most packets, but not all.
- header
    - endpoint
    - queue ID
    - DATA (Mostly bound by 0x7e, however, some data is unbound)

# Header
The header defines what type of packet and how long the data is. The header is always 5 bytes long and 
is always present in a packet. The header is not counted towards the data length.

See the table below for a breakdown of this example header: `23 00 00 00 1a`

| byte | value | description                          |
|------|-------|--------------------------------------|
| 0    | 0x23  | packet type                          |
| 1    | 0x00  | ?                                    |
| 2    | 0x00  | ?                                    |
| 3    | 0x00  | data length multiplier (value * 256) |
| 4    | 0x1a  | packet length, convert to int = 26   |

- packet multiplier example: `0x23 0x00 0x00 0x02 0x03` = 2 * 256 = 512 + 3 (last byte is data len) = 515
- **header length is not included in data length**

## 0x23
This is what I assume to be an auth packet. It includes an authorization code that can be pulled from the 
cloud using nikshrivs cync_data.json exporter.

- The endpoint is set by this packet

### Example packet
**Actual auth code zeroed out.**

```text
> 2024/03/11 00:14:18.000813563  length=31 from=0 to=30
 23 00 00 00 1a 03 39 87 c8 57 00 10 31 65 30 37     #.....9..W..1e07
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 3c     ...............<
```

| byte  | value               | description |
|-------|---------------------|-------------|
| 5     | 0x03                | ?           |
| 6 - 9 | 0x39 0x87 0xc8 0x57 | endpoint    |


### Response
The server responds with a 0x28 packet: `0x28 0x00 0x00 0x00 0x02 0x00 0x00`


## 0xc3
This seems to be a device connection packet, the device will not respond to commands without replying to this request.

### Example packet
```text
```

### Response
The server responds with a 0xc8 packet: `0xC8 0x00 0x00 0x00 0x0B 0x0D 0x07 0xE8 0x03 0x0A 0x01 0x0C 0x04 0x1F 0xFE 0x0C`

## 0xd3
This is a ping from the device to the server.

### Example packet
```text
```

### Response
The server responds with a 0xd8 packet, with no data: `0xd8 0x00 0x00 0x00 0x00`

## 0xa3
This seems to be a packet that the Cync app sends out to all devices when it connects.
The endpoint that is included in this packet is then used for 0x73/0x83 data channel packets.

### Response
The devices and server send back a 1MB (1024 byte) `0xab 0x00 0x00 0x03` response that contains the ascii chars `xlink_dev`. 
The endpoint and queue id are a part of the packet seemingly to ack the request.

## 0x43
These seem to be device status packets. It can contain more than one devices status. 
The status is 19 bytes long for each device. Sometimes there are incorrect devices, IDK why (they are ignored).

### Example packet
```text
< 2024/03/19 19:51:29.071705  length=354 from=3147 to=3500
 43 00 00 01 5d 16 b0 56 fc 01 01 06 05 00 10 0b  C...]..V........
 01 64 0e ff ff ff 01 00 0b 00 00 00 00 00 00 06  .d..............
 00 10 08 00 00 fe 00 00 f0 01 14 0b 00 00 00 00  ................
 00 00 07 00 10 c7 00 00 00 00 00 00 00 14 0b 00  ................
 00 00 00 00 00 08 00 10 31 01 64 0e 00 00 00 00  ........1.d.....
 14 0b 00 00 00 00 00 00 09 00 10 90 01 64 0e 00  .............d..
 00 00 00 14 0b 00 00 00 00 00 00 0a              ............
 00 10 09 01 64 37 00 00 00 00 14 0b 00 00 00 00  ....d7..........
 00 00 0b 00 10 07 00 00 fe 00 00 f0 01 14 0b 00  ................
 00 00 00 00 00 0c 00 10 02 01 64 32 00 00 00 01  ..........d2....
 ff 0b 00 00 00 00 00 00 0d 00 10 01 01 64 fe e0  .............d..
 00 00 00 ff 0b 00 00 00 00 00 00 0e 00 10 24 01  ..............$.
 64 0e 00 00 00 00 14 0b 00 00 00 00 00 00 0f 00  d...............
 10 dc 00 00 00 00 00 00 00 14 0b 00 00 00 00 00  ................
 00 10 00 10 05 01 64 00 00 00 00 01 14 0b 00 00  ......d.........
 00 00 00 00 11 00 10 30 01 64 0e 00 00 00 00 14  .......0.d......
 0b 00 00 00 00 00 00 12 00 10 06 01 64 00 00 00  ............d...
 00 01 14 0b 00 00 00 00 00 00 13 00 10 04 01 64  ...............d
 00 00 00 00 01 14 0b 00 00 00 00 00 00 14 00 10  ................
 9e 01 64 0e 00 00 00 00 14 0b 00 00 00 00 00 00  ..d.............
 15 00 10 0a                                      ....
 01 64 33 00 00 00 00 14 0b 00 00 00 00 00 00 16  .d3.............
 00 10 03 01 64 01 00 00 00 01 ff 0b 00 00 00 00  ....d...........
 00 00                                            ..
```
- header: `43 00 00 01 5d` (349 bytes, pkt mltplier 1*256 + 93 = 349)
- endpoint: `16 b0 56 fc`
- queue id: `01 01 06`
- status structure (19 bytes): `05 00 10 0b 01 64 0e ff ff ff 01 00 0b 00 00 00 00 00 00`


### Status structure
`05 00 10 0b 01 64 0e ff ff ff 01 00 0b 00 00 00 00 00 00`

Extracted status: `05 00 10 0b 01 64 0e ff ff ff 01`

| byte | value      | description                                                                 |
|------|------------|-----------------------------------------------------------------------------|
| 0    | 0x05 = 5   | item? increments with each struct                                           |
| 1    | 0x00 = 0   | ?                                                                           |
| 2    | 0x10 = 16  | ?                                                                           |
| 3    | 0x0b = 11  | device id                                                                   |
| 4    | 0x01 = 1   | state                                                                       |
| 5    | 0x64 = 100 | brightness                                                                  |
| 6    | 0x0e = 14  | temp > 100 means RGB data (so this bulb is in white                         |
| 7    | 0xff = 256 | R                                                                           |
| 8    | 0xff       | G                                                                           |
| 9    | 0xff       | B                                                                           |
| 10   | 0x01       | I've seen when this byte is 0, the data is stale.                           |
| 11   | 0x00       | this bulb is in a group with a dimmer, this btye is diff for only this bulb |


### Response
The server responds with a 0x48 packet: `0x48 0x00 0x00 0x00 0x03 0x01 0x01 0x00`

## 0x73
This is a bi-directional data channel packet. 
- The endpoint is the same as the 0xa3 packet.
- Control packets are sent to the device using 0x73 packets.
- All data sent is bound by 0x7e.
- Bluetooth mesh info is requested and replied to over 0x73 packets.

### Example packet
```text
# Control packet

```

### Response
The server responds with a 0x7b packet: `0x7b 0x00 0x00 0x00 0x07 <endpoint: 4 bytes> <queue id: 3 bytes>`

## 0x83
This is a bi-directional data channel packet. I am unsure of what exactly this channel is.

- Device firmware version is sent using 0x83 packets.
- Device self status updates are sent using 0x83 packets.
- Possibly devices joining the mesh happen on this channel?

### Example packet
```text
# device firmware version
```

### Response
The server responds with a 0x88 packet: `0x88 0x00 0x00 0x00 0x03 <queue id: 3 bytes>`



# Unknown
"""text
# 2 devices join the mesh. ID 2 and 3 (both BT only bulbs)
03/16/24 21:45:48.0033 DEBUG - cync-lan cync-lan:533 -> 10.0.2.215:extract: Extracting packets from 43 bytes of raw data
83 00 00 00 26 39 87 c8 57 00 5e 00 7e 11 00 00 00 fa d0 14 00 fe 03 00 05 00 ff ff ea 11 02 05 a1 00 00 00 00 00 00 00 00 8b 7e

11 00 00 00 fa d0   14 00   fe  03 00 05 00  ff  ff   ea  11 02 05  a1 00 00 00 00 00 00 00 00  8b
17  0  0  0 [ctrl]  20  0  255   3  0  5  0 256 256  234  17 ID id 161  0  0  0  0  0  0  0  0 139
17  0  0  0 [ctrl]  20  0  25   28 51  7  0 256 256  234  17 02 07 161  1  3  1  0  0  0  0  0   1

03/16/24 21:45:54.0995 DEBUG - cync-lan cync-lan:533 -> 10.0.2.215:extract: Extracting packets from 43 bytes of raw data
83 00 00 00 26 39 87 c8 57 00 5f 00 7e 11 00 00 00 fa d0 14 00 19 22 33 07 00 ff ff ea 11 02 07 a1 01 03 01 00 00 00 00 00 01 7e

11 00 00 00 fa d0   14 00  19  22 33 07 00  ff  ff   ea  11 02 07  a1 01 03 01 00 00 00 00 00 01
17  0  0  0 [ctrl]  20  0  25  28 51  7  0 256 256  234  17 ID id 161  1  3  1  0  0  0  0  0  1

"""
