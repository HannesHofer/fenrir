from unittest import TestCase, main as unittestmain
from unittest.mock import patch, mock_open, call
from random import choice
from string import ascii_letters
from fenrircore import filehandler


class FilehandlerTestCase(TestCase):
    def setUp(self):
        self.passphrase = ''.join(choice(ascii_letters) for i in range(15))
        self.sourcefilepath = '/tmp/sourcefile'
        self.destinationfilepath = '/tmp/destinationfile'
        self.plaintext = ''.join(choice(ascii_letters) for i in range(2048))

    def encrypt(self):
        mymock = mock_open(read_data=self.plaintext)
        with patch('builtins.open', mymock):
            filehandler.encrypt(self.sourcefilepath, self.destinationfilepath, self.passphrase, None)
            mymock.assert_has_calls([call(self.sourcefilepath, 'r'),
                                     call(self.destinationfilepath, 'w')],
                                    any_order=True)
            writedata = mymock().write.call_args[0][0]
            assert writedata != self.plaintext
            self.ciphertext = writedata

    def decrypt(self):
        assert hasattr(self, 'ciphertext')
        mymock = mock_open(read_data=self.ciphertext)
        with patch('builtins.open', mymock):
            filehandler.decrypt(self.sourcefilepath, self.destinationfilepath, self.passphrase, None)
            mymock.assert_has_calls([call(self.sourcefilepath, 'r'),
                                     call(self.destinationfilepath, 'w')],
                                    any_order=True)
            writedata = mymock().write.call_args[0][0]
            assert writedata == self.plaintext

    def test_crypt(self):
        self.encrypt()
        self.decrypt()


if __name__ == '__main__':
    unittestmain()
