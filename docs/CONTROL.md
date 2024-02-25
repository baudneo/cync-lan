# Pulled from
cync-lan source repo [issue](https://github.com/iburistu/cync-lan/issues/1#issuecomment-1579559684)

# From the linked issue

For turning the lights on.:
```
115, 0, 0, 0, 31, 0, 0, 0, 0, 0, 0, 0, 126, 134 (this number is incremented by the server for each command but it does not need to change), 0, 0, 0, 248, 208, 13, 0, 134 (duplicate of the incremental number), 0, 0, 0, 0, 3 (This is the light ID), 0, 208, 17, 2, 0 (off), 0, 0, 73 (checksum = incremental number - 64 (not sure why) + ID), 126
```
To turn on, the 0 changes to a 1 and the checksum increases by 1

To change color:
```
115, 0, 0, 0, 34, 0, 0, 0, 0, 0, 0, 0, 126, 65 (incremental number), 0, 0, 0, 248, 240, 16, 0, 65, 0, 0, 0, 0, 1 (ID), 0, 240, 17, 2, 1, 255, 254, 255 (R), 4 (G), 0 (B), 70 (Checksum = incremental + ID + RGB, 126
```

To change brightness 48%
```
115, 0, 0, 0, 34, 0, 0, 0, 0, 0, 0, 0, 126, 136 (incremental number), 0, 0, 0, 248, 240, 16, 0, 136, 0, 0, 0, 0, 1 (ID), 0, 240, 17, 2, 1, 48 (Brightness), 255, 255, 255, 255, 185 (Checksum = incremental + ID + Brightness), 126
```

I have also seen the device ID set to 0 and a 128 or 255 in the next place which can be used to control groups. Managing each light independently is a good start for me. I'm not super familiar with JavaScript but I will try to integrate my changes and get this server to work with this protocol.

# My breakdown of the structs
I will breakdown the packets.

## On/Off packet
```text
orig:  115, 0, 0, 0, 31, 0, 0, 0, 0, 0, 0, 0, 126, 134 (this number is incremented by the server for each command but it does not need to change), 0, 0, 0, 248, 208, 13, 0, 134 (duplicate of the incremental number), 0, 0, 0, 0, 3 (This is the light ID), 0, 208, 17, 2, 0 (off), 0, 0, 73 (checksum = incremental number - 64 (not sure why) + ID), 126
int:   115, 0, 0, 0, 31, 0, 0, 0, 0, 0, 0, 0, 126, 134, 0, 0, 0, 248, 208, 13, 0, 134, 0, 0, 0, 0, 3, 0, 208, 17, 2, 0, 0, 0, 73, 126
hex:   73 00 00 00 1f 00 00 00 00 00 00 00 7e 86 00 00 00 f8 d0 0d 0 86 00 00 00 00 03 00 d0 11 2 0 0 0 49 7e
[73 00 00 00] [1f] [00 00 00 00] [00 00 00] [7e] {86 00 00 00 f8 d0 0d 0 86 00 00 00 00 03 00 d0 11 2 0 0 0 49} [7e]
    [73 00 00 00] header
    [1f] header id 
    [00 00 00 00] queue id
    [00 00 00] msg id 
    [7e] start boundary
    { 86 00 00 00   f8   d0  0d 00   86 00 00 00 00 03 00   d0  11  2  0  0  0  49} data: hex
    [134, 0, 0, 0, 248, 208, 13, 0, 134, 0, 0, 0, 0, 3, 0, 208, 17, 2, 0, 0, 0, 73] data: int
     inc                             inc             id                st    checksum
     inc = incremental number - this number is incremented by the server for each command but it does not need to change
     st = state; 1 for on, 0 for off
     checksum = incremental number - 64 (not sure why) + id
        134 [inc] - 64 = 70
        + 3 [id] = 73
    [7e] stop boundary
```

## Color control packet
```text
orig: 115, 0, 0, 0, 34, 0, 0, 0, 0, 0, 0, 0, 126, 65 (incremental number), 0, 0, 0, 248, 240, 16, 0, 65, 0, 0, 0, 0, 1 (ID), 0, 240, 17, 2, 1, 255, 254, 255 (R), 4 (G), 0 (B), 70 (Checksum = incremental + ID + RGB), 126
int:  115, 0, 0, 0, 34, 0, 0, 0, 0, 0, 0, 0, 126, 65, 0, 0, 0, 248, 240, 16, 0, 65, 0, 0, 0, 0, 1, 0, 240, 17, 2, 1, 255, 254, 255, 4, 0, 70, 126
hex:  73 00 00 00 22 00 00 00 00 00 00 00 7e 41 00 00 00 f8 f0 10 0 41 00 00 00 00 01 00 f0 11 2 1 ff fe ff 4 0 46 7e
[73 00 00 00] [22] [00 00 00 00] [00 00 00] [7e] {41 00 00 00 f8 f0 10 0 41 00 00 00 00 1 00 f0 11 2 1 ff fe ff 4 0 46} [7e]
    [73 00 00 00] header
    [22] header id 
    [00 00 00 00] queue id
    [00 00 00] msg id 
    [7e] start boundary
    {41 00 00 00   f8   f0  10 00  41 00 00 00 00  01 00   f0  11 02  01    ff    fe  ff   4  0  46} data: hex
    [65, 0, 0, 0, 248, 240, 16, 0, 65, 0, 0, 0, 0,  1, 0, 240, 17, 2,  1,  255,  254, 255, 4, 0, 70] data: int
     inc                           inc             id                 st   bri   tmp   R   G  B  checksum
     inc = incremental number - this number is incremented by the server for each command but it does not need to change
     st = state
     bri = brightness, should only be 0-100
     tmp = white temperature 0-100, ive seen status packets that set temp to > 100 to signal it is an RGB status update. So this makes sense that temp is set to > 100
     R G B = color values 0-255
     checksum = inc + id + R + G + B 
        65 [inc] + 1 [id] = 66
        + 255 [R] = 66 (255 is a complete wrap around)
        + 4 [G] = 70
        + 0 [B] = 70
    [7e] stop boundary
```



## Brightness control packet    

```text
orig: 115, 0, 0, 0, 34, 0, 0, 0, 0, 0, 0, 0, 126, 136 (incremental number), 0, 0, 0, 248, 240, 16, 0, 136, 0, 0, 0, 0, 1 (ID), 0, 240, 17, 2, 1, 48 (Brightness), 255, 255, 255, 255, 185 (Checksum = incremental + ID + Brightness), 126
int:  115, 0, 0, 0, 34, 0, 0, 0, 0, 0, 0, 0, 126, 136, 0, 0, 0, 248, 240, 16, 0, 136, 0, 0, 0, 0, 1, 0, 240, 17, 2, 1, 48, 255, 255, 255, 255, 185, 126
hex:  73 00 00 00 22 00 00 00 00 00 00 00 7e 88 00 00 00 f8 f0 10 00 88 00 00 00 00 01 00 f0 11 02 01 30 ff ff ff ff b9 7e
[73 00 00 00] [22] [00 00 00 00] [00 00 00] [7e] {88 00 00 00 f8 f0 10 0 88 00 00 00 00 1 00 f0 11 2 1 30 ff ff ff ff b9} [7e]
    [73 00 00 00] header
    [22] header id 
    [00 00 00 00] queue id
    [00 00 00] msg id 
    [7e] start boundary
    {88  00 00 00   f8   f0  10 00  88  00 00 00 00  01 00   f0  11 02  01    30    ff  ff    ff   ff   b9} data: hex
    [136, 0, 0, 0, 248, 240, 16, 0, 136, 0, 0, 0, 0,  1, 0, 240, 17, 2,  1,  48,   255, 255, 255, 255, 185] data: int
     inc                            inc              id                 st   bri   tmp   R    G    B   checksum
     inc = incremental number - this number is incremented by the server for each command but it does not need to change
     st = state
     bri = brightness, should only be 0-100
     tmp = white temperature 0-100, ive seen status packets that set temp to > 100 to signal it is an RGB status update. So this makes sense that temp is set to > 100
     R G B = color values 0-255
     checksum = inc + id + bri 
        136 [inc] + 1 [id] = 137
        + 48 [bri] = 185
    [7e] stop boundary
```

## Group / Room control
> I have also seen the device ID set to 0 and a 128 or 255 in the next place which can be used to control groups.

Sounds to me like 128 is group or room and 255 is the other. Which byte is room/group ID though?

I havent gotten to groups and rooms yet. I his will update this when I do.

# Final thoughts

This control data lines up with the packets ive been seeing. When I start testing control, I will update this section