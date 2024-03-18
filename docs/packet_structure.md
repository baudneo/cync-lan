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
> 2024/02/25 21:28:36.000283244  length=31 from=16866 to=16896
 43 00 00 00 1a 39 87 c8 57 01 01 06 06 00 10 08 01 50 64 00 00 00 01 14 07 00 00 00 00 00 00
```
- header: `43 00 00 00 1a`
- endpoint: `39 87 c8 57`
- queue id: `01 01 06`
- inner data: `06 00 10 08 01 50 64 00 00 00 01 14 07 00 00 00 00 00 00`


### Status structure
`06 00 10 08 01 50 64 00 00 00 01 14 07 00 00 00 00 00 00`

Extracted status: `08 01 50 64 00 00 00 01`

| byte | value | description                                               |
|------|-------|-----------------------------------------------------------|
| 0    | 0x08  | device id                                                 |
| 1    | 0x01  | state                                                     |
| 2    | 0x50  | brightness                                                |
| 3    | 0x64  | temp - 254 means RGB data                                 |
| 4    | 0x00  | R                                                         |
| 5    | 0x00  | G                                                         |
| 6    | 0x00  | B                                                         |
| 7    | 0x01  | is_good, ive seen when this byte is 0, the data is stale. |


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

### Example packet
```text
# device firmware version
```

### Response
The server responds with a 0x88 packet: `0x88 0x00 0x00 0x00 0x03 <queue id: 3 bytes>`

