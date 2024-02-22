# Status Packet

| Byte | Value | Description                   |
| ---- | ----- |-------------------------------|
| 1    | 131   | Unknown                       |
| 2    | 0     | Unknown                       |
| 3    | 0     | Unknown                       |
| 4    | 0     | Unknown                       |
| 5    | 37    | Unknown                       |
| 6    | 57    | Unknown                       |
| 7    | 135   | Unknown                       |
| 8    | 166   | Unknown                       |
| 9    | 214   | Unknown                       |
| 10   | 0     | Unknown                       |
| 11   | *59   | Decremented by unknown amount |
| 12   | 0     | Unknown                       |
| 13   | 126   | Unknown                       |
| 14   | 0     | Unknown                       |
| 15   | 0     | Unknown                       |
| 16   | 0     | Unknown                       |
| 17   | 0     | Unknown                       |
| 18   | 250   | Unknown                       |
| 19   | 219   | Unknown                       |
| 20   | 19    | Unknown                       |
| 21   | 0     | Unknown                       |
| 22   | 100   | Decremented by 1 every report |
| 23   | 34    | Unknown (id?)                 |
| 24   | 17    | Unknown                       |
| 25   | 8     | Unknown                       |
| 26   | 0     | Unknown                       |
| 27   | 8     | Unknown                       |
| 28   | 0     | Unknown                       |
| 29   | 219   | Unknown                       |
| 30   | 17    | Unknown                       |
| 31   | 2     | Unknown                       |
| 32   | 1     | Unknown                       |
| 33   | *!0   | Device On/Off                 |
| 34   | 99    | Unknown                       |
| 35   | 100   | Unknown                       |
| 36   | 255   | Unknown                       |
| 37   | 98    | Unknown                       |
| 38   | 0     | Unknown                       |
| 39   | 0     | Unknown                       |
| 40   | 0     | Unknown                       |
| 41   | *172  | RSSI ?                        |
| 42   | 126   | Unknown                       |
| 43   | 67    | Unknown                       |
| 44   | 0     | Unknown                       |
| 45   | 0     | Unknown                       |
| 46   | 0     | Unknown                       |
| 47   | 26    | Unknown                       |
| 48   | 57    | Unknown                       |
| 49   | 135   | Unknown                       |
| 50   | 166   | Unknown                       |
| 51   | 214   | Unknown                       |
| 52   | 1     | Unknown                       |
| 53   | 1     | Unknown                       |
| 54   | 6     | Unknown                       |
| 55   | 5     | Unknown                       |
| 56   | 0     | Unknown                       |
| 57   | 16    | Unknown                       |
| 58   | 8     | Unknown                       |
| 59   | *!0   | Device On/Off                 |
| 60   | **0   | off=0, on=99 ??               |
| 61   | 100   | Unknown                       |
| 62   | 255   | Unknown                       |
| 63   | 98    | Unknown                       |
| 64   | 0     | Unknown                       |
| 65   | 1     | Unknown                       |
| 66   | 0     | Unknown                       |
| 67   | 8     | Unknown                       |
| 68   | 0     | Unknown                       |
| 69   | 0     | Unknown                       |
| 70   | 0     | Unknown                       |
| 71   | 0     | Unknown                       |
| 72   | 0     | Unknown                       |
| 73   | 0     | Unknown                       |

# Control Packet

**UNTESTED**

Data from an issue on the cync-lan repo, I was able to get the following information:

36 bytes long

## Turn On
```log
CTL: (115, 0, 0, 0, 31, 0,    0,   0,   0, 0,   0, 0, 126, 1, 0, 0, 0, 248, 208, 13, 0, 134  0,   0, 0, 0, 3, 0, 208, 17, 2, 0,   0, 0, 73, 126
```

| Byte | Value | Description    |
| ---- |-------|----------------|
| 1    | 115   | Unknown        |
| 2    | 0     | Unknown        |
| 3    | 0     | Unknown        |
| 4    | 0     | Unknown        |
| 5    | 31    | Unknown        |
| 6    | 0     | Unknown        |
| 7    | 0     | Unknown        |
| 8    | 0     | Unknown        |
| 9    | 0     | Unknown        |
| 10   | 0     | Unknown        |
| 11   | 0     | Unknown        |
| 12   | 0     | Unknown        |
| 13   | 126   | Unknown        |
| 14   | 1     | Increment by 1 |
| 15   | 0     | Unknown        |
| 16   | 0     | Unknown        |
| 17   | 0     | Unknown        |
| 18   | 248   | Unknown        |
| 19   | 208   | Unknown        |
| 20   | 13    | Unknown        |
| 21   | 0     | Unknown        |
| 22   | 134   | Increment by 1 |
| 23   | 0     | Unknown        |
| 24   | 0     | Unknown        |
| 25   | 0     | Unknown        |
| 26   | 0     | Unknown        |
| 27   | 3     | ID             |
| 28   | 0     | Unknown        |
| 29   | 208   | Unknown        |
| 30   | 17    | Unknown        |
| 31   | 2     | Unknown        |
| 32   | 0     | ON/OFF         |
| 33   | 0     | Status OFF/ON  |
| 34   | 0     | Unknown        |
| 35   | 73    | Checksum       |
| 36   | 126   | Unknown        |


