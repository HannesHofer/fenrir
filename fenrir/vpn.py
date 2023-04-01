#!/usr/bin/env python3

from os import unlink, mkfifo, O_RDWR, O_NONBLOCK, fdopen, open as osopen
from os.path import dirname, join, exists
from subprocess import Popen
from argparse import ArgumentParser
from time import sleep
from . filehandler import filehandler
from . firewall import Firewall
from signal import signal, SIGINT, SIGTERM
from sqlite3 import connect, OperationalError, Row
from sys import stdout
from logging import error, debug, basicConfig, INFO, DEBUG
from hashlib import md5
from select import select
from json import loads, dumps


class VPN:
    """ class to handle VPN config/connection

    Handles VPN Configuration
    handle connection and setup from config file(s)
    """
    def __init__(self, inputinterface='eth0', vpninterface='tun0', password=None,
                 dbpath='/var/cache/fenrir/fenrir.sqlite') -> None:
        """ initialization

        :param interface: if given use as VPN interface
        :param dbpath: path to vpn settings database
        :param password: password for encryption
        """
        self.inputinterface = inputinterface
        self.vpninterface = vpninterface
        self.dbpath = dbpath
        self.pipepath = str(join(dirname(self.dbpath), 'fenrirvpn.pipe'))
        self.endnow = False
        self.password = password
        self.connectionprofiles = {}
        self.vpnconnectionprocesses = {}
        self.vpnauthfiles = {}
        self.passwordvalid = self.checkpassword()

    def doend(self, signum, frame) -> None:
        """ stop running program once signal is received

        signum and frame are needed in order to map method as signal handler
        """
        self.endnow = True

    def checkpassword(self) -> bool:
        """ check wether or not current password is valid """
        with connect(f'file:{self.dbpath}?mode=ro', timeout=10, check_same_thread=False, uri=True) as db:
            cursor = db.cursor()
            resp = cursor.execute('SELECT username FROM vpnprofiles LIMIT 1;').fetchone()
            if resp:
                fh = filehandler(passphrase=self.password)
                return fh.checkpassword(ciphertext=resp[0])
        return False

    def handleobsoletes(self, obsoletes=None):
        if not obsoletes:
            obsoletes = self.vpnconnectionprocesses.keys() - self.connectionprofiles.keys()
        for obsolete in obsoletes:
            debug(f'removing obsolete connection for {obsolete} ...')
            self.vpnconnectionprocesses[obsolete].terminate()
            counter = 0
            # stop and terminate processes
            while not self.vpnconnectionprocesses[obsolete].poll() and counter < 10:
                counter += 1
                sleep(0.1)
            if counter >= 10:
                self.vpnconnectionprocesses[obsolete].kill()

            # delete obsolete config files
            for _, configfile in self.vpnauthfiles[obsolete].items():
                debug(f'removing obsolete config file: {configfile}')
                unlink(configfile)

            try:
                interface = 'tun' + md5(obsolete.encode('utf-8')).hexdigest()[:3]
                Firewall.disable(input_interface=self.inputinterface, output_interface=interface)
            except Exception as e:
                error(f'unable to set up firewall: {str(e)}. functionality limited to scan only.')

            del self.vpnconnectionprocesses[obsolete]
            del self.vpnauthfiles[obsolete]

    def handlepipeaction(self, data) -> dict:
        try:
            jsondata = loads(data)
        except ValueError as e:
            print(f'could not decode {data} to valid json: {str(e)}')
            return
        if 'command' not in jsondata or 'value' not in jsondata:
            debug(f'no command or value in josn: {data}')
            return

        match jsondata['command']:
            case 'setpassword':
                if self.passwordvalid:
                    return {'error': True, 'response': 'valid password is already set'}
                self.password = jsondata['value']
                self.passwordvalid = self.checkpassword()
                return {'error': False, 'response': f'given password is {"correct" if self.passwordvalid else "invalid"}'}
            case 'ispasswordset':
                return {'error': False, 'response': self.passwordvalid}
            case _:
                pass
        return {}

    def handlepipe(self):
        if not exists(self.pipepath):
            mkfifo(self.pipepath)

        fd = osopen(self.pipepath, O_RDWR | O_NONBLOCK)
        response = ''
        with fdopen(fd, 'r') as pipe:
            rlist, _, _ = select([pipe], [], [], 10)
            if rlist:
                try:
                    response = self.handlepipeaction(pipe.read())
                except Exception as e:
                    debug(f'Error in read of pipe: {str(e)}')
                    return
        if response:
            wfd = osopen(self.pipepath, O_RDWR | O_NONBLOCK)
            with fdopen(wfd, 'w') as writepipe:
                writepipe.write(dumps(response))
                writepipe.flush()
                sleep(1)

    def handleconnections(self) -> None:
        if not self.passwordvalid:
            debug('refusing to handle VPN Connections since correct password is not set')
            self.passwordvalid = self.checkpassword()
            return
        for profilename in self.connectionprofiles.keys():
            # new connection -> create conntection folder and files
            if profilename not in self.vpnconnectionprocesses.keys():
                debug(f'starting connection process for {profilename}...')
                fh = filehandler(passphrase=self.password)
                # create common auth file for username and password
                encuser = self.connectionprofiles[profilename]['username']
                encpass = self.connectionprofiles[profilename]['password']
                authfile = fh.decrypttofile(encuser.decode('utf-8'))
                tmppass = fh.decrypttofile(encpass.decode('utf-8'))
                with open(authfile, 'a') as writefile:
                    with open(tmppass, 'r') as readfile:
                        writefile.write('\n' + readfile.read())
                unlink(tmppass)
                config = fh.decrypttofile(self.connectionprofiles[profilename]['config'].decode('utf-8'))
                interface = self.vpninterface
                if not self.connectionprofiles[profilename]['isdefault']:
                    interface = 'tun' + md5(profilename.encode('utf-8')).hexdigest()[:3]
                debug(f'using {config} for config, {authfile} for auth and {interface} as interface...')
                self.vpnauthfiles[profilename] = {'config': config, 'authfile': authfile}
                startcmd = ['/usr/sbin/openvpn', '--auth-nocache']
                startcmd += ['--config', self.vpnauthfiles[profilename]['config']]
                startcmd += ['--auth-user-pass', self.vpnauthfiles[profilename]['authfile']]
                startcmd += ['--dev', interface]
                try:
                    Firewall.enable(input_interface=self.inputinterface, output_interface=interface)
                except Exception as e:
                    error(f'unable to set up firewall: {str(e)}. functionality limited to scan only.')
                self.vpnconnectionprocesses[profilename] = Popen(startcmd)
            # restart process if needed
            elif self.vpnconnectionprocesses[profilename].poll():
                debug(f're-starting no longer runnging vpn process for profile: {profilename} ...')
                for _, configfile in self.vpnauthfiles[profilename].items():
                    unlink(configfile)
                del self.vpnconnectionprocesses[profilename]
                del self.vpnauthfiles[profilename]

    def refreshvpnconfig(self) -> None:
        """ (re-)read vpn config from database """
        try:
            dbprofiles = {}
            with connect(f'file:{self.dbpath}?mode=ro', timeout=10, check_same_thread=False, uri=True) as db:
                db.row_factory = Row
                cursor = db.cursor()
                result = cursor.execute("""SELECT name, config, username, password, isdefault from
                                           vpnprofiles WHERE ondemand = 0 OR (ondemand = 1 AND isneeded = 1);""")
                for row in result.fetchall():
                    dbprofiles[row['name']] = {'config': row['config'], 'username': row['username'],
                                               'password': row['password'], 'isdefault': row['isdefault']}
                # check if connection parameters changed
                refreshprofiles = []
                for profile, data in self.connectionprofiles.items():
                    if profile not in dbprofiles:
                        continue
                    if data != dbprofiles[profile]:
                        debug(f'configuration data for {profile} changed. updating connection...')
                        refreshprofiles.append(profile)
                if len(refreshprofiles) > 0:
                    self.handleobsoletes(obsoletes=refreshprofiles)
                self.connectionprofiles = dbprofiles
        except OperationalError as e:
            debug(f'unable to open Database at {self.settingsdb}: {e}')

    def run(self) -> None:
        signal(SIGINT, self.doend)
        signal(SIGTERM, self.doend)

        while not self.endnow:
            self.refreshvpnconfig()
            self.handleconnections()
            self.handleobsoletes()
            self.handlepipe()

        # cleanup configfiles and firewall rules
        for profilename, configfiles in self.vpnauthfiles.items():
            if not self.connectionprofiles[profilename]['isdefault']:
                interface = 'tun' + md5(profilename.encode('utf-8')).hexdigest()[:3]
                try:
                    Firewall.disable(input_interface=self.inputinterface, output_interface=interface)
                except Exception as e:
                    error(f'unable to delete {self.inputinterface} -> {self.interface}: {str(e)}.')
            for _, configfile in configfiles.items():
                debug(f'removing configfile: {configfile}')
                unlink(configfile)

        try:
            Firewall.disable(input_interface=self.inputinterface, output_interface=self.vpninterface)
        except Exception as e:
            error(f'unable to delete {self.inputinterface} -> {self.vpninterface}: {str(e)}.')


def vpn(inputinterface=None, vpninterface=None, password=None, dbpath=None) -> None:
    """ set up connection with given parameters

    :param interface: interface for vpn traffic routing
    :param dbpath: path to vpn settings database
    """
    VPN(inputinterface=inputinterface, vpninterface=vpninterface,
        password=password, dbpath=dbpath).run()


def main() -> None:
    """ main method

    parse given commandline arguments
    start vpn handling
    """
    parser = ArgumentParser()
    parser.add_argument('--inputinterface', help='interface for traffic to be routed to VPN', default=None)
    parser.add_argument('--vpninterface', help='interface for VPN traffic', default=None)
    parser.add_argument('--dbpath', help='path to vpn settings database', default='/var/cache/fenrir/fenrir.sqlite')
    parser.add_argument('--password', help='use given password for encryption/decryption', default=None)
    parser.add_argument('--debug', help='activate debug logging', action='store_true')
    args = parser.parse_args()
    loglevel = DEBUG if args.debug else INFO
    basicConfig(stream=stdout, level=loglevel)
    debug(f'path: {args.dbpath}')
    vpn(dbpath=args.dbpath, inputinterface=args.inputinterface,
        vpninterface=args.vpninterface, password=args.password)


if __name__ == "__main__":
    main()
