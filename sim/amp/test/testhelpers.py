
import unittest
import logging
import random

logger = logging.getLogger()

def random_octets(size):
    return ''.join([chr(random.randint(0, 255)) for ix in range(size)])

class TestCase(unittest.TestCase):
    
    def assertDataEqual(self, strA, strB):
        self.assertSequenceEqual(strA, strB)
