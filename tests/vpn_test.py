from unittest import TestCase, main as unittestmain
from unittest.mock import patch, Mock
from random import choice
from string import ascii_letters
from fenrir import vpn


class VPNTest(TestCase):
    def setUp(self):
        pass

    def generic(self, interface='', authfile='', configfile=''):
        mymock = Mock()
        with patch('fenrir.vpn.Popen', mymock):
            myvpn = vpn.VPN(interface=interface, authfile=authfile, configfile=configfile)
            myvpn.endnow = True
            myvpn.connect()
        return mymock

    def test_interface(self):
        theinterface = ''.join(choice(ascii_letters) for i in range(15))
        mymock = self.generic(interface=theinterface)
        callargs = mymock.call_args_list[0][0][0]
        assert '--dev' in callargs
        assert theinterface in callargs

    def test_authfile(self):
        theauthfile = ''.join(choice(ascii_letters) for i in range(15))
        mymock = self.generic(authfile=theauthfile)
        callargs = mymock.call_args_list[0][0][0]
        assert '--auth-user-pass' in callargs
        assert theauthfile in callargs

    def test_config(self):
        theconfig = ''.join(choice(ascii_letters) for i in range(15))
        mymock = self.generic(configfile=theconfig)
        callargs = mymock.call_args_list[0][0][0]
        assert '--config' in callargs
        assert theconfig in callargs


if __name__ == '__main__':
    unittestmain()
