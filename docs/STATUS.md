# Status Packets

`0x43` is a status packet which elicits `0x48` replies. There seems to be different data reported in the data struct.


```text
## This device is id: 7

# device sends a ping to the queue/msg ids?
> 2024/02/25 21:31:07.000328434  length=12 from=17700 to=17711
 43 00 00 00 07 39 87 c8 57 01 01 06
 [43 00 00 00] [07] [39 87 c8 57] [01 01 06]
    [43 00 00 00] header
    [07] header id
    [39 87 c8 57] queue id
    [01 01 06] msg id

# server 0x48 ack
< 2024/02/25 21:31:07.000413430  length=8 from=7889 to=7896
 48 00 00 00 03 01 01 00
> 2024/02/25 21:31:16.000334443  length=12 from=17712 to=17723
 43 00 00 00 07 39 87 c8 57 01 01 06
< 2024/02/25 21:31:16.000417049  length=8 from=7897 to=7904
 48 00 00 00 03 01 01 00

# 50 byte len status update seems to be a self status update packet. Unknown if header id is diff on other devices yet.
> 2024/02/25 21:28:32.000326388  length=50 from=16816 to=16865
 43 00 00 00 2d 39 87 c8 57 01 01 06 06 00 10 06 01 64 00 00 00 00 01 14 07 00 00 00 00 00 00 07 00 10 05 01 64 00 00 00 00 01 14 07 00 00 00 00 00 00
 [43 00 00 00] [2d] [39 87 c8 57] [01 01 06] {06 00 10 06 01 64 00 00 00 00 01 14 07 00 00 00 00 00 00 07 00 10 05 01 64 00 00 00 00 01 14 07 00 00 00 00 00 00}
 [43 00 00 00] header
    [2d] header id
    [39 87 c8 57] queue id
    [01 01 06] msg id 
    {06 00 10 06 01   64 00 00 00 00   01       14     07      00 00  00 00  00 00 07   00  10 05   01   64 00  00 00 00 01  14       07    00 00  00 00  00 00} data: hex
    [6, 0, 16, 6, 1, 100, 0, 0, 0, 0,   1,      20,     7,      0, 0,  0, 0,  0, 0, 7,   0, 16, 5,   1, 100, 0,  0, 0, 0, 1, 20,       7,    0, 0,  0, 0,  0, 0] data: int
     ?  (bnd)  id st bri tmp R  G  B    is good  ?    id-from   ?  ?   ?  ?   ?  ?  ?    (bnd)  id  st  bri  tmp R  G  B  gd  type? id-from  ?  ?   ?  ?   ?  ?
# device id: 6, state: 1, brightness: 100, temp: 0, R: 0, G: 0, B: 0 is_good: 1 --> is a plug
# device id: 5  state: 1, brightness: 100, temp: 0, R: 0, G: 0, B: 0 is_good: 1 --> is a plug
# is_good = 0/1, 1 means read the state. 0 means dont read the state data
     


< 2024/02/25 21:28:32.000409298  length=8 from=7401 to=7408
 48 00 00 00 03 01 01 00
 
# Regular length status packet
> 2024/02/25 21:28:36.000283244  length=31 from=16866 to=16896
 43 00 00 00 1a 39 87 c8 57 01 01 06 06 00 10 08 01 50 64 00 00 00 01 14 07 00 00 00 00 00 00
    [43 00 00 00] [1a] [39 87 c8 57] [01 01 06 06] {00 10 08 01 50 64 00 00 00 01 14 07 00 00 00 00 00 00}
    [43 00 00 00] header
    [1a] header id
    [39 87 c8 57] queue id
    [01 01 06] msg id 
    {06, 00  10  08  01   50    64 00 00 00  01  14      07      00 00 00 00 00 00} data: hex
    [6,   0, 16,  8,  1,  80,  100, 0, 0, 0,  1, 20,     7,      0, 0, 0, 0, 0, 0] data: int
    ?     (bnd)  id  st   bri  tmp  R  G  B   (bnd)    id-from?  ?  ?  ?  ?  ?  ?
    # device id: 8, state: 1, brightness: 80, temp: 100, R: 0, G: 0, B: 0 --> is a Wi-Fi/BT bulb


# Timestamp - header id: 0x34. Timestamp is after 0x2a
> 2024/02/25 22:06:28.000721012  length=57 from=32740 to=32796
 43 00 00 00 34 39 87 c8 57 01 01 06 c7 90 2a 32 30 32 34 30 32 32 35 3a 32 32 30 36 3a 2d 35 30 2c 30 30 30 30 30 2c 30 30 30 30 30 2c 30 30 30 30 30 2c 30 30 30 30 30 2c
 [43 00 00 00] [34] [39 87 c8 57] [01 01 06] {c7 90 2a 32 30 32 34 30 32 32 35 3a 32 32 30 36 3a 2d 35 30 2c 30 30 30 30 30 2c 30 30 30 30 30 2c 30 30 30 30 30 2c 30 30 30 30 30 2c} 
    [43 00 00 00] header
    [34] header id
    [39 87 c8 57] queue id
    [01 01 06] msg id
    {c7    90  2a  32  30  32  34  30  32  32  35  3a  32  32  30  36  3a  2d  35  30  2c  30  30  30  30  30  2c  30  30  30  30  30  2c  30  30  30  30  30  2c  30  30  30  30  30 2c} data: hex
    [199, 144, 42, 50, 48, 50, 52, 48, 50, 50, 53, 58, 50, 50, 48, 54, 58, 45, 53, 48, 44, 48, 48, 48, 48, 48, 44, 48, 48, 48, 48, 48, 44, 48, 48, 48, 48, 48, 44, 48, 48, 48, 48, 48 45] data: int
    
```