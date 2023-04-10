from unittest import TestCase, main as unittestmain
from unittest.mock import patch
from fenrircore import fenrir, __version__


class FenrirTestCase(TestCase):
    def setUp(self):
        self.fenrir = fenrir.Fenrir(inputinterface='eth0', vpninterface='tun0', dbpath='/tmp/fenrir.db', password=None)

    def test_version(self):
        assert __version__ == '0.5.0'

    def setup(self):
        with patch('fenrircore.fenrir.makedirs') as mkdirmock, \
             patch('fenrircore.fenrir.Firewall.forwarding') as forwardingmock, \
             patch('fenrircore.fenrir.Process') as processmock:
            self.fenrir.setUP()
            mkdirmock.assert_called_once()
            forwardingmock.assert_called_once()
            assert processmock.call_count == 3
            assert len(self.fenrir.processes) == 3

    def teardown(self):
        with patch('fenrircore.fenrir.kill') as killmock:
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
