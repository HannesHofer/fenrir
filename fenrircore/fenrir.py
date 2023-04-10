#!/usr/bin/env python3

from . firewall import Firewall
from . arper import arper
from . scanner import scan, printresults
from . vpn import vpn
from . getmacvendors import updatemacvendors
from signal import signal, SIGINT, SIGTERM
from time import sleep
from os import kill, makedirs, path
from sys import stdout
from logging import info, basicConfig, INFO, DEBUG
from multiprocessing import Process
from argparse import ArgumentParser
from sqlite3 import connect


class Fenrir:
    """ class to contain all ARP related methods

    Handles all ARP related stuff.
    Spoofing, Scanning etc. Also available from config.
    """
    def __init__(self, inputinterface, vpninterface, dbpath='/var/cache/fenrir/fenrir.sqlite', password=None) -> None:
        """ initialization

        :param inputinterface: interface for network traffic to be spoofed
        :param vpninterface: vpn interface to route spoofed traffic to
        :param dbpath: path to vpnsettings database
        :param password: use given password for vpnconfig encryption/decryption

        map sigterm and sigend to doend method allowing those signals to stop run method
        """
        self.inputinterface = inputinterface
        self.vpninterface = vpninterface
        self.dbpath = dbpath
        self.endnow = False
        self.password = password
        self.processes = []
        signal(SIGINT, self.doend)
        signal(SIGTERM, self.doend)

    def doend(self, signum, frame) -> None:
        """ stop running program once signal is received

        signum and frame are needed in order to map method as signal handler
        """
        self.endnow = True

    def initDB(self):
        """ initialize Database. Create needed tables """
        with connect(self.dbpath) as db:
            cursor = db.cursor()
            cursor.execute('CREATE TABLE IF NOT EXISTS settings(ip TEXT PRIMARY KEY, ACTIVE INTEGER DEFAULT 0);')
            cursor.execute('''CREATE TABLE IF NOT EXISTS ipconnectionmap(id INTEGER PRIMARY KEY AUTOINCREMENT,
                              name TEXT, ip TEXT);''')
            cursor.execute('''CREATE TABLE IF NOT EXISTS vpnprofiles(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT ,
                              description TEXT, isdefault BOOL, ondemand BOOL, isneeded BOOL default 0,
                              config BYTES, username BYTES, password BYTES);''')
            cursor.execute('''CREATE TABLE IF NOT EXISTS devices(mac TEXT PRIMARY KEY, ip TEXT,  vendor TEXT,
                              ACTIVE INTEGER DEFAULT 0, lastupdate TIMESTAMP DEFAULT CURRENT_TIMESTAMP);''')
            cursor.execute('''CREATE TABLE IF NOT EXISTS profilepassword(salt STRING NOT NULL, hash STRING NOT NULL, usedforencryption BOOL);''')

    def setUP(self) -> None:
        """ set up firewall, processes for run

        set up firewall config
        start needed processes vpn, arper, scanner
        """
        info('Fenrir starting...')
        info('Creating directories...')
        makedirs(path.dirname(self.dbpath), exist_ok=True)
        self.initDB()
        info('Firewall enabled. Starting arp handler...')
        self.processes.append(Process(target=arper, args=(self.inputinterface, False)))
        self.processes[-1].start()
        info('ARP handler started. Starting Scanner...')
        self.processes.append(Process(target=scan, args=(self.inputinterface, False)))
        self.processes[-1].start()
        info('Scanner startup complete. Starting VPN...')
        Firewall.forwarding(allow=True)
        self.processes.append(Process(target=vpn, args=(self.inputinterface, self.vpninterface,
                                                        self.password, self.dbpath)))
        self.processes[-1].start()
        info(f'VPN startup complete. watching Process {" ".join(str(p.pid) for p in self.processes)}')

    def tearDOWN(self) -> None:
        """ teardown run method - end processes

        end all processes gracefully.
        kill processes after grace period
        """
        for process in self.processes:
            info(f'got stop command. stopping process {process.pid}')
            kill(process.pid, SIGINT)

        counter = 0
        while counter < (5 * 30):
            if not any(p.is_alive() for p in self.processes):
                break
            sleep(0.2)
        else:
            info(
                'Could not end all processes. sending kill signal to remaining processes and quiting.')
            for p in self.processes:
                p.terminate()
                p.join()
        self.processes.clear()
        info('All managed processes ended. quiting.')

    def run(self) -> None:
        """ main running method until stop signal is recevied and doend member is set

        start and watch firewall, arphandler, scanner processes
        stop processes on doend
        """
        self.setUP()
        try:
            while not self.endnow:
                for process in self.processes:
                    if not process.is_alive():
                        process.start()
                counter = 0
                # sleep 30 seconds but check for term signals every 0.2 secs
                while not self.endnow and counter < (5 * 30):
                    sleep(0.2)
                    counter += 1
        except KeyboardInterrupt:
            info('got keyboard interrupt.')

        self.tearDOWN()


def main() -> None:
    """ main method

    initialize logging
    parse given commandline arguments
    start Fenrir main method
    """
    parser = ArgumentParser()
    parser.add_argument('--vpninterface', help='interface for VPN traffic', default='tun0')
    parser.add_argument('--inputinterface', help='interface for network scanning/intercepting', default='eth0')
    parser.add_argument('--dbpath', help='path to vpnconfig database', default='/var/cache/fenrir/fenrir.sqlite')
    parser.add_argument('--debug', help='activate debug logging', action='store_true')
    parser.add_argument('--scanonly', help='do network scan and print results', action='store_true')
    parser.add_argument('--password', help='use given password for vpnconfig encryption/decryption', default=None)
    parser.add_argument('--updatemacvendors', const='/var/cache/fenrir/macvendors.sqlite',
                        help='update macvendors and store to given path', default=None, nargs='?')
    args = parser.parse_args()
    loglevel = DEBUG if args.debug else INFO
    basicConfig(stream=stdout, level=loglevel)
    if args.scanonly:
        return printresults(args.inputinterface)
    elif args.updatemacvendors:
        return updatemacvendors(dbpath=args.updatemacvendors)
    Fenrir(inputinterface=args.inputinterface, vpninterface=args.vpninterface,
           dbpath=args.dbpath, password=args.password).run()


if __name__ == "__main__":
    main()
