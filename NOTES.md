# Status packets

These are packets received from a 'Direct Connect Full Color A19 Bulb' on firmware: 1.0.361

## Connected device status

The bulb is connected to the server and in the app (using mobile data) 
I am controlling the same bulb I am connected to.

### Turn Off
```
OFF: (131, 0, 0, 0, 37, 57, 135, 166, 214, 0, *59, 0, 126, 0, 0, 0, 0, 250, 219, 19, 0, 100, 34, 17, 8, 0, 8, 0, 219, 17, 2, 1, *!0, 99, 100, 255, 98, 0, 0, 0, *172, 126, 67, 0, 0, 0, 26, 57, 135, 166, 214, 1, 1, 6, 5, 0, 16, 8, *!0, **0, 100, 255, 98, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0)
```

### Turn On
```log
 ON: (131, 0, 0, 0, 37, 57, 135, 166, 214, 0, *58, 0, 126, 0, 0, 0, 0, 250, 219, 19, 0, *99?dec, 34, 17, 8, 0, 8, 0, 219, 17, 2, 1, 1, 99, 100, 255, 98, 0, 0, 0, 172, 126, 67, 0, 0, 0, 26, 57, 135, 166, 214, 1, 1, 6, 5, 0, 16, 8, 1, 99, 100, 255, 98, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0)
```

### Compare Off/On
```log
        1  2  3  4   5   6    7    8   9  10  11  12  13  14  15 16 17  18   19  20  21  22  23  24  25 26 27 28  29  30  31 32  33  34   35   36  37 38  39 40   41  42   43 44 45  46 47  48   49  50    51  52 53 54 55 56 57  58  59   60   61   62  63  64 65 66 67 68 69 70 71 72 73
OFF: (131, 0, 0, 0, 37, 57, 135, 166, 214, 0, *59, 0, 126, 0, 0, 0, 0, 250, 219, 19, 0, 100, 34, 17, 8, 0, 8, 0, 219, 17, 2, 1, *!0, 99, 100, 255, 98, 0, 0, 0, *172, 126, 67, 0, 0, 0, 26, 57, 135, 166, 214, 1, 1, 6, 5, 0, 16, 8, *!0, **0, 100, 255, 98, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0)
 ON: (131, 0, 0, 0, 37, 57, 135, 166, 214, 0, *58, 0, 126, 0, 0, 0, 0, 250, 219, 19, 0, *99, 34, 17, 8, 0, 8, 0, 219, 17, 2, 1, *!1, 99, 100, 255, 98, 0, 0, 0, *172, 126, 67, 0, 0, 0, 26, 57, 135, 166, 214, 1, 1, 6, 5, 0, 16, 8, *!1, *99, 100, 255, 98, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0)
OFF: (131, 0, 0, 0, 37, 57, 135, 166, 214, 0, *55, 0, 126, 0, 0, 0, 0, 250, 219, 19, 0, *98, 34, 17, 8, 0, 8, 0, 219, 17, 2, 1, *!0, 99, 100, 255, 98, 0, 0, 0, *170, 126, 67, 0, 0, 0, 26, 57, 135, 166, 214, 1, 1, 6, 5, 0, 16, 8, *!0, **0, 100, 255, 98, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0)
```

# Control Packets

From an issue on the cync-lan repo, I was able to get the following information:

```
For turning the lights on.:

115, 0, 0, 0, 31, 0, 0, 0, 0, 0, 0, 0, 126, 134 (this number is incremented by the server for each command but it does not need to change), 0, 0, 0, 248, 208, 13, 0, 134 (duplicate of the incremental number), 0, 0, 0, 0, 3 (This is the light ID), 0, 208, 17, 2, 0 (off), 0, 0, 73 (checksum = incremental number - 64 (not sure why) + ID), 126

To turn on, the 0 changes to a 1 and the checksum increases by 1

To change color:

115, 0, 0, 0, 34, 0, 0, 0, 0, 0, 0, 0, 126, 65 (incremental number), 0, 0, 0, 248, 240, 16, 0, 65, 0, 0, 0, 0, 1 (ID), 0, 240, 17, 2, 1, 255, 254, 255 (R), 4 (G), 0 (B), 70 (Checksum = incremental + ID + RGB, 126

To change brightness 48%

115, 0, 0, 0, 34, 0, 0, 0, 0, 0, 0, 0, 126, 136 (incremental number), 0, 0, 0, 248, 240, 16, 0, 136, 0, 0, 0, 0, 1 (ID), 0, 240, 17, 2, 1, 48 (Brightness), 255, 255, 255, 255, 185 (Checksum = incremental + ID + Brightness), 126

I have also seen the device ID set to 0 and a 128 or 255 in the next place which can be used to control groups. Managing each light independently is a good start for me. I'm not super familiar with JavaScript but I will try to integrate my changes and get this server to work with this protocol.
```