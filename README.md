[![Actions Status](https://github.com/HannesHofer/fenrir/workflows/Test/badge.svg)](https://github.com/HannesHofer/fenrir/actions)

# Fenrir routing service

## Introduction
Fenrir provides a user friendly way to route all traffic from configured trough a VPN tunnel.

This is done via ARP Spoofing. Determined default GW on `inputinterface` is spoofed to configured device.
Configuration is stored in `/var/cache/fenrir/settings.db`

## Installation
Fenrir is a pure python3 application. (3.6+)

### pip releases
```sh
> pip install fenrir
> fenrir --help
```
# Usage
Usage is documented in integrated help module.
```sh
> fenrir --help
```
## examples
### perform a scan on `wlan0` and quit
```sh
fenrir --scanonly --inputinterface wlan0
```

### intercept on `wlan0` and use vpn config in `tmp` folder 
```sh
fenrir --inputinterface wlan0 --vpnconfigfile /tmp/vpn.config --vpnauthfile /tmp/vpnauth.config
```

### intercept on `wlan0` and use vpn config in `tmp` folder where config is encrypted with default password
default password is hashed MAC of inputinterface for encrypted config when no password is given 
```sh
fenrir --inputinterface wlan0 --vpnconfigfile /tmp/vpn.config --vpnauthfile /tmp/vpnauth.config --vpnconfigisencrypted
```

### intercept on `wlan0` and use vpn config in `tmp` folder where config is encrypted with given password
```sh
fenrir --inputinterface wlan0 --vpnconfigfile /tmp/vpn.config --vpnauthfile /tmp/vpnauth.config --vpnconfigisencrypted --vpnconfigpassword thepassword
```
