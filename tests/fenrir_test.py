import unittest
from fenrir import __version__

class FenrirTestCase(unittest.TestCase):
    def test_version(self):
        assert __version__ == '0.1.0'
        
if __name__ == '__main__':
    unittest.main()
