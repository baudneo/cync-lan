### 0.0.6b1
- NOTE: always backup, I am a carpenter who does this in my spare time, not a software engineer
- Proxy / MITM mode: Devices connected to CyncLAN via TCP will have a 'MITM Mode' button exposed
  - Enabling will force the device to reconnect and all data will be proxied to the Cync cloud and logged to file and optionally to the log console
  - While MITM mode is enabled, the device will not be able to be used to send any commands to Cync devices, but it will still report device state changes (can read, no write)
  - It is recommended to have 1 TCP device connected that is not in MITM mode to be able to control the devices via HASS while you are gathering data on the MITM device
  - This is intended to be used to gather data on new devices and functionality that CyncLAN does not expose, so I can add support for it; dynamic / music / per segment lighting state/effects, thermostat, etc.
  - Currently only Cync devices support MITM mode, work is ongoing to allow Cync mobile apps and hopefully allow a way to add new devices to cloud accounts while network-wide DNS redirection is active.
  - See an example [work flow](https://github.com/baudneo/cync-lan/tree/add-mitm#workflow)
- Cloud API refresh token logic added
- Packet building logic refactoring
- Optimizations
- Add deviceType 151: Soft white decorative candle light (thanks [@tobyroworth](https://github.com/baudneo/cync-lan/commits?author=tobyroworth))

### 0.0.5b3
- add deviceTypes 53, 56, 155, 170

### 0.0.5b2
- BREAKING CHANGES:
  - Add encryption for the cloud token cache at rest; Fernet with static seeded PBKDF2HMAC key.
  - REQUIRES: Setting a random alphanumeric string for CYNC_SECRET_KEY in the App config

### 0.0.5b1
- BREAKING CHANGES:
  - Any automations or other logic relying on Cync switches being registered as `switch`es will need to be updated to use `light` instead.
- Cync switches are now exposed as `light` entities in Home Assistant.
  - This *should* allow for controlling Cync app rooms/groups; cync-lan will not be aware of what devices are part of what groups/rooms as the idea is to send the light switch commands (you will know what switch controls what devices).
  - You *should* be able to send the light switch RGB, brightness or white temp commands and the Cync group will change in unison, just like they do in the Cync app when you control a group/room, or a physical button press.
  - This assumes you have the switch setup to control the Cync devices logically instead of turning the mains power on/off to the circuit. It is untested with the latter.
  - Is there interest in instead of exposing switches as lights, expose the switches as switches and then also expose a light entity to control the group/room? Open an issue to discuss.
- Only the fan controller is still exposed as a switch, I dont have one to test if it can be grouped with other devices and targeted with RGB, etc. commands.
  - If you own a fan controller and can group it with other devices in the Cync app and then the fan controller can be used to control those Cync devices, please open an issue and we can try figuring something out. 

### 0.0.4b14
- DONT UPGRADE, this is a test for targeting cync groups/rooms
  - stephenwall-95 please test
  - typo: Light -> LIGHT

### 0.0.4b13
- DONT UPGRADE, this is a test for targeting cync groups/rooms
  - stephenwall-95 please test

### 0.0.4b12
- Add missing adjustable brightness to deviceType 125

### 0.0.4b11
- Add deviceType 128: 2700K A19 bulb

### 0.0.4b10
- Add deviceType 125: Paddle switch

### 0.0.4b9
- Add deviceType 40: Paddle switch

### 0.0.4b8
- Initial support for thermostat related quirks concerning non-thermostat devices
  - This does not add support for the thermostat, only allows exporting and controlling non-thermostat devices that are affected by a thermostat related quirk in their raw deviceID 

### 0.0.4b7
- Fix multi endpoint device export logic; pydantic dataclass was exported as yaml rather than the expected format

### 0.0.4b6
- DNS redirection guide for TP-Link Omada Controller, thanks [dnguyen800](https://github.com/dnguyen800)
- [Fan controllers moved from a 0-255](https://github.com/baudneo/cync-lan/commit/6a66d5557066bf4ff9acc0f1abcc6b13e1bf21fb) binary range to using a percentage style 0-100. Thanks @[tobyroworth](https://github.com/baudneo/cync-lan/commits?author=tobyroworth)
  - It's possible that anyone on older firmware may see issues, open an issue and we can try a firmware filter

- Added logic for older (abandoned?) GE Sol lamp device. Thanks @[lukabratzee](https://github.com/Lukabratzee)
  - [This PR contains code written by Claude sonnet](https://github.com/baudneo/cync-lan/pull/20). I am not levying any sort of opinion, just being transparent as people seem to want disclosure of this sort of thing
  - This may also allow backwards compatibility for anyone using old firmware devices


### 0.0.4b5
- Add deviceType 72: Full Color Dynamic Effects Premium Light Strip (16 / 32ft)
  - I don't own any dynamic lights, so I would need debug data from someone to get the dynamic effects / per bulb/ segment state working
  - There is a MITM proxy in the works to facilitate binary debugging for new functionality from unseen devices.
  
### 0.0.4b4
- Add deviceType 76: Full color dynamic cafe lights (24 / 48ft)
  

### 0.0.4b3
- Add better logging for unknown deviceTypes; devices CyncLAN has not seen before.
  - Before, things would 'just work' by brute force for unknown deviceTypes. Now, due to better class handling, we need \
  to know if the device is a light or a switch/plug/fan controller/thermostat/multi-endpoint device for things to work \
  as expected.
  - This requires adding unknown/unseen device `type` to the `device_info` hash map, devices that worked before 0.0.4 \
  **MAY NOT** work in > 0.0.4.
  - This is an easy fix, open an issue with the log line that has the device `type` number and a brief explanation of \
  what the device is and its capabilities: https://github.com/baudneo/cync-lan/issues/12
  - While I understand that this is annoying, this is better for everyone in the long run and as a perk to you, you \
  will get a better detailed MQTT device info page

### 0.0.4b2
- Fix unassigned var name type: name -> dev_name in config export process

### 0.0.4b1
- The underlying cync-lan lib has been merged into one source. Before, 2 versions were maintained for HASS / regular docker images
- Refactored ID handling logic to allow multiple endpoints per node
- Changed logic to view a physical Cync device as a `node` and endpoints as logical representations of the device state; allows multi-endpoint per node logic cleanly
- Aggressive online/offline handling causing false positive offline devices has been turned off while I investigate 
- [Ad-Guard DNS guide](https://github.com/baudneo/cync-lan/blob/python/docs/DNS.md#adguard-home) added to cync-lan DNS docs, thanks @[lbrpdx](https://github.com/baudneo/cync-lan/commits?author=lbrpdx)
- Add device types: 9, 47, 51, 67, 71 and 107
  - Support for device type: 67 -> Outdoor Dual Outlet Plug; required logic change to Node and endpoints
- MeshInfo response pagination fix; some devices/nodes stream the MeshInfo response over multiple packets, some devices send it all in one packet
- Refactoring and better online/offline handling ongoing
  - You may notice differences from < 0.0.4, please open issues for missing/broken/incomplete functionality 

### 0.0.3.b12
- Last checkpoint before merging underlying cync-lan libraries into one.

### 0.0.3b11
- make sure the cync_mesh.yaml exported file is overwritten by default in the HASS image

### 0.0.3b10
- Host tailwinds, animate.css and prism.js locally, removing the internet requirement to render the export page

### 0.0.3b9
- add `raw_debug` options to config. When enabled, will output binary data to/from TCP devices in the logs (VERY verbose)
- fix device type 107: switch to light

### 0.0.3b8
- typo fix: `model-info` to `model_info`: GH mobile editor strikes again

### 0.0.3b7
- add device types 47, 71 and 107

### 0.0.3b6
- fix `functools.partial` error

### 0.0.3b5
- split switch and plug logic

### 0.0.3b4
- fix brightness scale (was 0-255, we want 0-100)
- add device types 39, 57
  - 39: direct connect on/off paddle switch - neutral required
  - 57: direct connect on/off paddle switch - NO neutral required (same model # with a NN appended for No Neutral, good to know)
- Updated Github notifications so I actually receive notifications of issues/PR's, etc.
  - Sorry, I've been a bit stunned lately. Hopefully this is the last beta release before 0.0.3

### 0.0.3b3
- Fix new logic in 'supported_color_modes'
- Add device types: 17, 18 
  - 2700K dimmable bulbs [CLED199L2]
  - 18 may be the same bulb with a newer SoC

### 0.0.3b2
- Nothing of note

### 0.0.3b1
- Add default 'supported_color_modes' of 'brightness' in device / entity registration messages to stop throwing deprecation warnings (2025.3)
- Changed 'object_id' to 'default_entity_id' in device / entity registration messages ('object_id' retained for older versions)
- Add random delay (5-15s) after hass birth message before re-announcing device config and state.
  - Fixes no devices after a hass restart
- bumped min ver to get the fix out

### 0.0.2b2
- Add restart button to export: unhidden after receiving success from submitting OTP button
- Fix cached token reading: attempted to read a binary file in text mode
- Fix device closing logic: expected exception is now `pass`ed, proper input to asyncio.wait()
- Optimizations

### 0.0.2b1
- Add "state" key and value when updating brightness, temp or RGB. Even though hass docs say it is optional, HASS logs shows exceptions when this is omitted due to using direct access to a dict key: variable_dict["key"] instead of checking for key existence or using .get().

### 0.0.2a1
- Rough in fan support (WIP)
- optimizations

## 0.0.1
- Initial release