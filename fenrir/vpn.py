#!/usr/bin/env python3

from os import unlink
from subprocess import Popen
from argparse import ArgumentParser
from time import sleep
from fenrir.filehandler import filehandler
from signal import signal, SIGINT, SIGTERM


class VPN:
    """ class to handle VPN config/connection
    
    Handles VPN Configuration
    handle connection and setup from config file(s)
    """
    def __init__(self, interface=None, authfile=None, configfile=None, encrypted=False, password=None) -> None:
        """ initialization
        
        :param interface: if given use as VPN interface
        :param authfile: file for VPN authentication (user/password)
        :param configfile: configfile for VPN connection
        :param encrypted: set to True if authfile is encrypted
        :param password: password for encryption
        """
        self.interface = interface
        self.authfile = authfile
        self.configfile = configfile
        self.encrypted = encrypted
        self.endnow = False
        self.password = password

    def doend(self, signum, frame) -> None:
        """ stop running program once signal is received
        
        signum and frame are needed in order to map method as signal handler
        """
        self.endnow = True

    def connect(self) -> None:
        """ start vpn connection
        
        start openvpn with preset config 
        end process/connection when doend is set
        """
        startcmd = ['/usr/sbin/openvpn', '--auth-nocache']
        if self.configfile:
            startcmd += ['--config', self.configfile]
        if self.authfile:
            startcmd += ['--auth-user-pass', self.authfile]
        if self.interface:
            startcmd += ['--dev', self.interface]

        proc = Popen(startcmd)
        while not self.endnow:
            sleep(1)

        proc.kill()

    def run(self) -> None:
        """ main running method until stop signal is recevied and doend member is set
        
        decrypt set config and authfile if needed
        stop on signal term and int
        re-try to establish connection with 2 second backoff time        
        """
        if self.encrypted:
            fh = filehandler(passphrase=self.password)
            self.configfile = fh.decryptfile(self.configfile)
            self.authfile = fh.decryptfile(self.authfile)

        signal(SIGINT, self.doend)
        signal(SIGTERM, self.doend)

        backofftime = 2
        while not self.endnow:
            self.connect()
            sleep(backofftime)
            backofftime = backofftime * 2 if backofftime < 60 else 60

        if self.encrypted:
            unlink(self.configfile)
            unlink(self.authfile)


def vpn(interface, authfile, configfile, encrypted) -> None:
    """ set up connection with given parameters
    
    :param interface: interface for vpn traffic routing
    :param authfile: path to authentication file
    :param configfile: path to vpn config file
    :param encrypted: is config and authfile encrypted
    """
    VPN(interface=interface, authfile=authfile,
        configfile=configfile, encrypted=encrypted).run()


def main() -> None:
    """ main method
    
    parse given commandline arguments
    start vpn handling
    """
    parser = ArgumentParser()
    parser.add_argument(
        '--interface', help='interface for VPN traffic', default=None)
    parser.add_argument(
        '--authfilepath', help='path for openvpn user-pass auth file', default='/storage/nordvpn.auth')
    parser.add_argument(
        '--configfilepath', help='path for openvpn config file', default='/storage/nordvpn.conf')
    parser.add_argument(
        '--encrypted', help='file is encrypted. decrypt and store plaintext file in /run', action='store_true')
    args = parser.parse_args()
    vpn(interface=args.interface, authfile=args.authfilepath,
        configfile=args.configfilepath, encrypted=args.encrypted)


if __name__ == "__main__":
    main()
