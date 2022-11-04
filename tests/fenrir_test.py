from unittest import TestCase, main as unittestmain
from unittest.mock import patch
import sys
sys.path.insert(0, '/home/hannes/Work/fenrir/fenrir-lib/fenrir')
from fenrir import fenrir, __version__


class FenrirTestCase(TestCase):
    def setUp(self):
        self.fenrir = fenrir.Fenrir(inputinterface='eth0', vpninterface='tun0', vpnconfigfile='',
                                    vpnauthfile='', vpnisencrypted=False, password=None)

    def test_version(self):
        assert __version__ == '0.1.0'

    def setup(self):
        with patch('fenrir.fenrir.makedirs') as mkdirmock, \
             patch('fenrir.fenrir.Firewall') as fwmock, \
             patch('fenrir.fenrir.Process') as processmock:
            self.fenrir.setUP()
            fwmock.assert_called_once()
            mkdirmock.assert_called_once()
            assert processmock.call_count == 3
            assert len(self.fenrir.processes) == 3

    def teardown(self):
        with patch('fenrir.fenrir.kill') as killmock:
            for process in self.fenrir.processes:
                process.is_alive.return_value = False
            self.fenrir.tearDOWN()
            assert killmock.call_count == 3
            assert len(self.fenrir.processes) == 0

    def test_setupANDteardown(self):
        self.setup()
        self.teardown()


if __name__ == '__main__':
    unittestmain()
