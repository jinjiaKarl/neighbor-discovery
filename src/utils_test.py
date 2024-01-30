import unittest
import utils
from constant import *

class TestDistance(unittest.TestCase):
    def test_distance_out_of_range(self):
        lat1 = '1'
        lng1 = 1
        lat2 = 100
        lng2 = 100
        dis = utils.calculate_distance(lat1, lng1, lat2, lng2)
        self.assertTrue(dis > RANGE)

    def test_distance_in_range(self):
        lat1 = 1
        lng1 = 1
        lat2 = 5
        lng2 = 5
        dis = utils.calculate_distance(lat1, lng1, lat2, lng2)
        self.assertTrue(dis < RANGE)





if __name__ == "__main__":
    unittest.main()
    