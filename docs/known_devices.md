Devices known to work, kind of work, and known not to work are listed here.

# Known Good
- Cync: Direct connect **bulbs** (Full color, Decorative [edison], white temp, dimmable)
    - Direct connect products are Wi-Fi and Bluetooth LE using a realtek chip
- Cync/C by GE: Bluetooth LE only bulbs \**needs at least 1 Wi-Fi device to act as a TCP<->BT bridge*
    - C by GE BT only: These are telink based devices 
- Cync: Indoor smart plug
    - Outdoor plug should also work, currently unconfirmed
- Cync: Wired switches (on/off, dimmer, white temp control) [motion/ambient light data is not exposed, switch uses it internally]
- Cync: Full color LED light strip [responds slightly differently than other devices]
    - Outdoor light strip should also work, currently unconfirmed

# Known Bad
- Basically anything with a battery as its power source. They are BTLE only and are not supported by this script **yet**.
    - Wire free switch OR dimmer [white temp control].
    - Sensors [motion, temperature/humidity, etc.]

# Future devices
Devices I do not own, but would like to add support for. If you can get me good `socat` logs, I can add support for them.
- Dynamic lights (Sound/Music sync, segmented leds)
- Fan controller
- Thermostat
- Cameras (I'm not sure if cync-lan will support them, but I would like to try)