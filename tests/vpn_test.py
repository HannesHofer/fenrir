from unittest import TestCase, main as unittestmain
from unittest.mock import patch, Mock
from fenrircore import vpn


class VPNTest(TestCase):
    def setUp(self):
        pass

    def test_init(self):
        with patch('signal.signal'), \
             patch('fenrircore.vpn.VPN.checkpassword') as checkpwd, \
             patch('fenrircore.fenrir.Firewall.disable') as fwdisable:
            myvpn = vpn.VPN(inputinterface='eth0', vpninterface='tun0', dbpath='/tmp/test')
            checkpwd.assert_called_once()
            myvpn.endnow = True
            myvpn.run()
            assert 'eth0' in str(fwdisable.call_args_list[0])
            assert 'tun0' in str(fwdisable.call_args_list[0])


if __name__ == '__main__':
    unittestmain()
