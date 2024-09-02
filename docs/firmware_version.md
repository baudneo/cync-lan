I am noticing that there are differences in firmware versions, there seems to be backwards compatibility though.

Device version has 2 formats;`x.y.zzz` for newer cync devices and `x.y` for older c by ge devices.
The device only sends a version HTTP packet on an irregular (so far) basis, it is unknown if the version can be requested like mesh info can.

## CYNC
There are Wifi+BT (mains powered) devices and BT only devices (battery powered).
These devices can control the old C by GE BT only devices.

- `1.x.yyy` seems to have the same HTTP packet structures and lengths
    - `1.0.xxx` seems to be Direct Connect (A19) Bulbs and Plugs
    - `1.3.xxx` seems to be Decorative (Edison) Direct Connect (ST19) Bulbs (White, WW+RGB)
- `2.3.xxx` seems to be battery (wire free) switches (BT only) 
- `3.x.yyy` seems to be Full Color Direct Connect Smart Light Strip (LED Strip) Controller
    - has different HTTP packet structures and lengths than `1.x.yyy`

## C by GE
I think these are BT only devices. These can be controlled by the CYNC BT mesh.

- `4.6` - Full Color Smart Bulb (A19)