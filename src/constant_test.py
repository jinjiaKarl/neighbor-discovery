import unittest
import constant

class TestGetValue(unittest.TestCase):
    def test_get_cfg(self):
        data = constant.GLOBAL_OBJ
        assert data['port'] == 8080


if __name__ == "__main__":
    unittest.main()
    