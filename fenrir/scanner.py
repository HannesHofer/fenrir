#!/usr/bin/env python3

from scapy.all import ARP, Ether, srp
from pyroute2 import IPRoute
from ipaddress import ip_network
from . getmacvendors import getvendorformac
from . arper import getmydefaultgws
from socket import AF_INET
from datetime import datetime
from time import time, sleep
from sqlite3 import connect, OperationalError, Cursor
from logging import info, debug, basicConfig, INFO, DEBUG
from sys import stdout
from argparse import ArgumentParser
from signal import signal, SIGINT, SIGTERM


class Scanner:
    """ class to handle MACAddress/IP scanning

    Handles scanning for mac and ip addresses
    creates database and stores found mac/ip addresses
    get default route to determine and exclude default gateways
    """
    def __init__(self, dbpath='/var/cache/fenrir/fenrir.sqlite', interface='eth0', clear=False) -> None:
        """ initialization

        :param dbpath: path to store/create database of scanned MAC/IPs
        :param interface: interface to scan for MAC/IPs
        """
        self.endnow = False
        self.dbpath = dbpath
        self.interface = interface
        if clear:
            self.clearresults()

    def doend(self, signum, frame) -> None:
        """ stop running program once signal is received

        signum and frame are needed in order to map method as signal handler
        """
        self.endnow = True

    def clearresults(self) -> Cursor:
        """ reset netdevices """
        with connect(self.dbpath) as db:
            return db.cursor().execute('DELETE FROM devices;')

    def getmydeviceroutes(self) -> list:
        """ get device routes for given interface

        return all device routes on given interface
        """
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

    def scan(self, networks) -> map:
        """ scan for MAC/IPs in given networks

        :param networks: networks to scan to

        check if IP is in settings set to active if present
        """
        clients = {}
        for net in networks:
            mypacket = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=net)
            result = srp(mypacket, iface=self.interface,
                         timeout=10, verbose=0)[0]
            for sent, received in result:
                clients[received.psrc] = {'mac': received.hwsrc}
                debug(f'found {received.psrc} with MAC {received.hwsrc}')
        return clients

    def setactive(self, clients):
        """ set configured clients to active

        :param clients: clients to set active if configured in database

        set configured MACs in DB to active
        """
        try:
            with connect(f'file:{self.dbpath}?mode=ro', timeout=10, check_same_thread=False, uri=True) as db:
                cursor = db.cursor()
                result = cursor.execute('SELECT ip, active from settings;')
                for row in result.fetchall():
                    if len(row) < 2 or row[0] not in clients.keys():
                        continue
                    clients[row[0]].update(
                        {'active': True if int(row[1]) > 0 else False})
        except OperationalError as e:
            debug(f'unable to open Database at {self.settingsdb}: {e}')
        return clients

    def updatedatabase(self, devices=None, excludeIPs=[]) -> None:
        """ update database with given devices

        :param devices: given map of active ips
        :param excludeIPs: IPs to be ignored

        update netdevices database with given devices but ignore excludeips
        """
        db = connect(self.dbpath)
        cur = db.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS devices(mac TEXT PRIMARY KEY, ip TEXT,  vendor TEXT,
                    ACTIVE INTEGER DEFAULT 0, lastupdate TIMESTAMP DEFAULT CURRENT_TIMESTAMP);''')
        now = datetime.now().strftime("%B %d, %Y %I:%M%p")
        for ip, additionalinfo in devices.items():
            if ip in excludeIPs:
                continue
            active = additionalinfo['active'] if 'active' in additionalinfo.keys() else 0
            cur.execute('INSERT OR REPLACE INTO devices(mac, ip, vendor, active, lastupdate) values(?, ?, ?, ?, ?)',
                        (additionalinfo['mac'], ip, getvendorformac(additionalinfo['mac']), active, now))
        db.commit()
        db.close()

    def continousupdate(self, singleshot=False) -> None:
        """ update database with hosts on preset interface

        :param singleshot: if set quit after 1 scan otherwise scan continously

        get default GWs to ignore gateway from scanning
        get device routes for scanning
        do scan & update database
        on continous update sleep 30 secs
        """
        while not self.endnow:
            mydefaultgws = getmydefaultgws(self.interface)
            devicenet = self.getmydeviceroutes()
            startmillis = round(time() * 1000)
            if devicenet and mydefaultgws:
                devices = self.setactive(self.scan(networks=devicenet))
                self.updatedatabase(devices=devices, excludeIPs=mydefaultgws)
            if singleshot:
                break
            exectime = round(time() * 1000) - startmillis
            sleeptime = 30 - (exectime/1000)
            debug(f'sleeptime: {sleeptime} exectime: {exectime}')
            while sleeptime > 0:
                sleeptime = sleeptime - 1
                if self.endnow:
                    break
                sleep(1)

    def run(self, singleshot=False, debuglog=False) -> None:
        """ run scanning

        :param singleshot: abort scan after 1 scan if set to True
        :param debug: set logging to debug if true

        initialize logging and map singals to doend method
        start scanning with given parameters
        """
        basicConfig(stream=stdout, level=DEBUG if debuglog else INFO)
        signal(SIGINT, self.doend)
        signal(SIGTERM, self.doend)
        info('statring device scanning...')
        self.continousupdate(singleshot=singleshot)
        info('device scanning stoped.')


def scan(interface, singleshot, debug=False) -> None:
    """ do scan on given interface

    :param interface: scan on given interface
    :param sigleshot: quit after 1 scan if set to True
    :param debug: set logging to debug if true
    """
    Scanner(interface=interface).run(singleshot=singleshot, debuglog=debug)


def printresults(interface) -> None:
    """ do scan on given interface and print results

    :param interface: scan on given interface
    """
    scanner = Scanner(interface=interface)
    routes = scanner.getmydeviceroutes()
    devices = scanner.scan(networks=routes)
    for ip, macmap in devices.items():
        thevendor = getvendorformac(macmap["mac"])
        vendortext = '' if not thevendor else ' from Vendor ' + thevendor
        print(f'found MAC {macmap["mac"]}{vendortext} with IP {ip}')


def main() -> None:
    """ main method

    parse given commandline arguments
    start Firewall
    """
    parser = ArgumentParser()
    parser.add_argument(
        '--singleshot', help='exit after first completed scan', action='store_true')
    parser.add_argument(
        '--print', help='print found devices int network (implies --singleshot)', action='store_true')
    parser.add_argument(
        '--interface', help='interface for device scanning', default='eth0')
    parser.add_argument('--debug', help='activate debug logging', action='store_true')
    args = parser.parse_args()
    if args.print:
        return printresults(args.interface)
    scan(interface=args.interface, singleshot=args.singleshot, debug=args.debug)


if __name__ == "__main__":
    main()
