from unittest import TestCase, main as unittestmain
from unittest.mock import patch, Mock
from fenrir import vpn


class VPNTest(TestCase):
    def setUp(self):
        pass

    def test_init(self):
        with patch('signal.signal'), \
             patch('fenrir.fenrir.Firewall.disable') as fwdisable:

            myvpn = vpn.VPN(inputinterface='eth0', vpninterface='tun0')
            myvpn.endnow = True
            myvpn.run()
            assert 'eth0' in str(fwdisable.call_args_list[0])
            assert 'tun0' in str(fwdisable.call_args_list[0])



if __name__ == '__main__':
    unittestmain()
