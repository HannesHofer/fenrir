#!/usr/bin/env python3

from fenrir.firewall import Firewall
from fenrir.arper import arper
from fenrir.scanner import scan
from fenrir.vpn import vpn
from signal import signal, SIGINT, SIGTERM
from time import sleep
from os import kill, makedirs
from sys import stdout
from logging import info, basicConfig, INFO, DEBUG
from multiprocessing import Process
from argparse import ArgumentParser


class Fenrir:
    def __init__(self, inputinterface, vpninterface, vpnconfigfile='', vpnauthfile='', vpnisencrypted=False):
        self.inputinterface = inputinterface
        self.vpninterface = vpninterface
        self.vpnconfigfile = vpnconfigfile
        self.vpnauthfile = vpnauthfile
        self.vpnisencrypted = vpnisencrypted
        self.endnow = False
        self.processes = []
        self.__dbpath__ = '/var/cache/fenrir/'
        signal(SIGINT, self.doend)
        signal(SIGTERM, self.doend)

    def doend(self, signum, frame):
        self.endnow = True

    def run(self):
        info('Fenrir starting...')
        info('Creating directories...')
        makedirs(self.__dbpath__, exist_ok=True)
        fw = Firewall()
        info('Enabling Firewall...')
        fw.enable(input_interface=self.inputinterface,
                  output_interface=self.vpninterface)
        info('Firewall enabled. Starting arp handler...')
        self.processes.append(Process(target=arper, args=(self.inputinterface, False)))
        self.processes[-1].start()
        info('ARP handler started. Starting Scanner...')
        self.processes.append(
            Process(target=scan, args=(self.inputinterface, False)))
        self.processes[-1].start()
        info('Scanner startup complete. Starting VPN...')
        self.processes.append(Process(target=vpn, args=(
            self.vpninterface, self.vpnauthfile, self.vpnconfigfile, self.vpnisencrypted)))
        self.processes[-1].start()
        info(
            f'VPN startup complete. watching Process {" ".join(str(p.pid) for p in self.processes)}')
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
        info('All managed processes ended. quiting.')


def main():
    parser = ArgumentParser()
    parser.add_argument(
        '--vpninterface', help='interface for VPN traffic', default='tun0')
    parser.add_argument(
        '--inputinterface', help='interface for network scanning/intercepting', default='eth0')
    parser.add_argument(
        '--vpnconfigfile', help='config file for vpn service (openvpn)', default='/storage/nordvpn.conf')
    parser.add_argument(
        '--vpnauthfile', help='auth file (username/password) for vpnservice', default='/storage/nordvpn.auth')
    parser.add_argument('--vpnconfigisencrypted',
                        help='specify if VPN config and authfile are encrypted', action='store_true', default=True)
    parser.add_argument('--debug', help='activate debug logging', action='store_true')
    args = parser.parse_args()
    loglevel = DEBUG if args.debug else INFO
    basicConfig(stream=stdout, level=loglevel)
    Fenrir(inputinterface=args.inputinterface, vpninterface=args.vpninterface,
           vpnauthfile=args.vpnauthfile, vpnconfigfile=args.vpnconfigfile,
           vpnisencrypted=args.vpnconfigisencrypted).run()


if __name__ == "__main__":
    main()
