# Status packets

These are packets received from a 'Direct Connect Full Color A19 Bulb' on firmware: 1.0.361

## Connected device status

The bulb is connected to the server and in the app (using mobile data) 
I am controlling the same bulb I am connected to.

### Turn Off
        1  2  3  4   5   6    7    8   9  10  11  12  13  14  15 16 17  18   19  20  21  22  23  24  25 26 27 28  29  30  31 32  33  34   35   36  37 38  39 40   41  42   43 44 45  46 47  48   49  50    51  52 53 54 55 56 57  58  59   60   61   62  63  64 65 66 67 68 69 70 71 72 73
OFF: (131, 0, 0, 0, 37, 57, 135, 166, 214, 0, *59, 0, 126, 0, 0, 0, 0, 250, 219, 19, 0, 100, 34, 17, 8, 0, 8, 0, 219, 17, 2, 1, *!0, 99, 100, 255, 98, 0, 0, 0, *172, 126, 67, 0, 0, 0, 26, 57, 135, 166, 214, 1, 1, 6, 5, 0, 16, 8, *!0, **0, 100, 255, 98, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0)
 ON: (131, 0, 0, 0, 37, 57, 135, 166, 214, 0, *58, 0, 126, 0, 0, 0, 0, 250, 219, 19, 0, *99, 34, 17, 8, 0, 8, 0, 219, 17, 2, 1, *!1, 99, 100, 255, 98, 0, 0, 0, *172, 126, 67, 0, 0, 0, 26, 57, 135, 166, 214, 1, 1, 6, 5, 0, 16, 8, *!1, *99, 100, 255, 98, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0)
OFF: (131, 0, 0, 0, 37, 57, 135, 166, 214, 0, *55, 0, 126, 0, 0, 0, 0, 250, 219, 19, 0, *98, 34, 17, 8, 0, 8, 0, 219, 17, 2, 1, *!0, 99, 100, 255, 98, 0, 0, 0, *170, 126, 67, 0, 0, 0, 26, 57, 135, 166, 214, 1, 1, 6, 5, 0, 16, 8, *!0, **0, 100, 255, 98, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0)
# App sending turn off to lamp
OFF: (131  0  0  0  37  55  150  19   47   3  49   0  126 23  0  0  0  250  219  19  0  186  36  17  1  0  1  0  219  17  2  1  *1   44  254  224   0  0  0  0  217   126                  
OFF: (131, 0, 0, 0, 37, 57, 135, 166, 214, 0, *55, 0, 126, 0, 0, 0, 0, 250, 219, 19, 0, *98, 34, 17, 8, 0, 8, 0, 219, 17, 2, 1, *!0, 99, 100, 255, 98, 0, 0, 0, *170, 126, 67, 0, 0, 0, 26, 57, 135, 166, 214, 1, 1, 6, 5, 0, 16, 8, *!0, **0, 100, 255, 98, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0)

---

Create a table for the above 73 bytes in the device status packet.

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
| 23   | 34    | Unknown                       |
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



### Turn On

```log
 ON: (131, 0, 0, 0, 37, 57, 135, 166, 214, 0, *58, 0, 126, 0, 0, 0, 0, 250, 219, 19, 0, *99?dec, 34, 17, 8, 0, 8, 0, 219, 17, 2, 1, 1, 99, 100, 255, 98, 0, 0, 0, 172, 126, 67, 0, 0, 0, 26, 57, 135, 166, 214, 1, 1, 6, 5, 0, 16, 8, 1, 99, 100, 255, 98, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0)
```
