#!/usr/bin/env python3

from scapy.all import ARP, Ether, srp
from pyroute2 import IPRoute
from ipaddress import ip_network
from fenrir.getmacvendors import getvendorformac
from fenrir.arper import getmydefaultgws
from socket import AF_INET
from datetime import datetime
from time import time, sleep
from sqlite3 import connect, OperationalError
from logging import info, debug, basicConfig, INFO
from sys import stdout
from argparse import ArgumentParser
from signal import signal, SIGINT, SIGTERM


class Scanner:
    def __init__(self, dbpath='/var/cache/fenrir/', interface='eth0') -> None:
        self.endnow = False
        self.settingsdb = dbpath + 'settings.sqlite'
        self.netdevices = dbpath + 'netdevices.sqlite'
        self.interface = interface

    def doend(self, signum, frame):
        self.endnow = True

    def getmydeviceroutes(self):
        targetnetworks = set()
        for route in IPRoute().get_addr(family=AF_INET):
            tmpnetworks = set()
            for attr in route['attrs']:
                if attr[0] == 'IFA_ADDRESS':
                    devrt = str(ip_network(
                        f'{attr[1]}/{route["prefixlen"]}', strict=False))
                    debug(f'found device route {devrt}')
                    tmpnetworks.add(devrt)
                elif attr[0] == 'IFA_LABEL':
                    if attr[1] == self.interface:
                        targetnetworks.update(tmpnetworks)
                        break
        return list(targetnetworks)

    def scan(self, networks):
        clients = {}
        for net in networks:
            mypacket = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=net)
            result = srp(mypacket, iface=self.interface,
                         timeout=10, verbose=0)[0]
            for sent, received in result:
                clients[received.psrc] = {'mac': received.hwsrc}

        try:
            with connect(f'file:{self.settingsdb}?mode=ro', timeout=10, check_same_thread=False, uri=True) as db:
                cursor = db.cursor()
                result = cursor.execute('SELECT ip, active from settings;')
                for row in result.fetchall():
                    if len(row) < 2 or row[0] not in clients.keys():
                        continue
                    clients[row[0]].update(
                        {'active': True if int(row[1]) > 0 else False})
        except OperationalError as e:
            debug(f'unable to open Database at {self.settingsdb}')
        return clients

    def updatedatabase(self, devices=None, excludeIPs=[]):
        db = connect(self.netdevices)
        cur = db.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS devices(mac TEXT PRIMARY KEY, ip TEXT,  vendor TEXT,
                    ACTIVE INTEGER DEFAULT 0, lastupdate TIMESTAMP DEFAULT CURRENT_TIMESTAMP);''')
        now = datetime.now().strftime("%B %d, %Y %I:%M%p")
        for ip, additionalinfo in devices.items():
            if ip in excludeIPs:
                continue
            active = additionalinfo['active'] if 'active' in additionalinfo.keys(
            ) else 0
            cur.execute('INSERT OR REPLACE INTO devices(mac, ip, vendor, active, lastupdate) values(?, ?, ?, ?, ?)',
                        (additionalinfo['mac'], ip, getvendorformac(additionalinfo['mac']), active, now))
        db.commit()
        db.close()

    def continousupdate(self, singleshot=False):
        while not self.endnow:
            mydefaultgws = getmydefaultgws(self.interface)
            startmillis = round(time() * 1000)
            devicenet = self.getmydeviceroutes()
            devices = self.scan(networks=devicenet)
            self.updatedatabase(devices=devices, excludeIPs=mydefaultgws)
            exectime = round(time() * 1000) - startmillis
            sleeptime = 30 * 1000 - exectime
            while sleeptime > 0:
                sleeptime = sleeptime - 1
                if self.endnow:
                    break
                sleep(1)
            if singleshot:
                break

    def run(self, singleshot=False):
        basicConfig(stream=stdout, level=INFO)
        signal(SIGINT, self.doend)
        signal(SIGTERM, self.doend)
        info('statring device scanning...')
        self.continousupdate(singleshot=singleshot)
        info('device scanning stoped.')


def scan(interface, singleshot):
    Scanner(interface=interface).run(singleshot=singleshot)


def main():
    parser = ArgumentParser()
    parser.add_argument(
        '--singleshot', help='exit after first completed scan', action='store_true')
    parser.add_argument(
        '--interface', help='interface for device scanning', default='eth0')
    args = parser.parse_args()
    scan(interface=args.interface, singleshot=args.singleshot)


if __name__ == "__main__":
    main()
