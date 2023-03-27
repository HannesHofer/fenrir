from unittest import TestCase, main as unittestmain
from unittest.mock import patch, Mock
from random import choice
from string import ascii_letters
from fenrir import vpn


class VPNTest(TestCase):
    def setUp(self):
        pass

    def generic(self, interface=''):
        mymock = Mock()
        with patch('fenrir.vpn.Popen', mymock):
            myvpn = vpn.VPN(interface=interface)
            myvpn.endnow = True
        return mymock





if __name__ == '__main__':
    unittestmain()
