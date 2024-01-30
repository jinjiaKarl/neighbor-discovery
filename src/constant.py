import os
import yaml


def get_env_variable(key):
    return os.getenv(key)

def update_cfg_value(data, key, value):
    if value:
        data[key] = value

def parse_noise_strength():
    noise_strength = GLOBAL_OBJ['noise_strength']
    return noise_strength[0], noise_strength[1]

def parse_array(key):
    v = GLOBAL_OBJ[key]
    return v[0], v[1]

# environment variables have higher priority than cfg.yaml
def get_cfg_value():
    with open('cfg.yaml', 'r') as f:
        data = yaml.safe_load(f)
        rx = get_env_variable('RX_IPADDR')
        tx = get_env_variable('TX_IPADDR')
        lat = get_env_variable('LAT')
        lng = get_env_variable('LNG')
        update_cfg_value(data, 'rx_ipaddr', rx)
        update_cfg_value(data, 'tx_ipaddr', tx)
        if lat:
            data['location'][0] = lat
        if lng:
            data['location'][1] = lng
        return data

GLOBAL_OBJ = get_cfg_value()
NAME = GLOBAL_OBJ['name']
PORT = GLOBAL_OBJ['port']
WEB_PORT = GLOBAL_OBJ['web_port']
CA_IPADDR = GLOBAL_OBJ['ca_ipaddr']
CA_PORT = GLOBAL_OBJ['ca_port']
BUFFER_SIZE = GLOBAL_OBJ['buffer_size']
ECCDH = GLOBAL_OBJ['eccdh']
IS_CERTIFICATE = GLOBAL_OBJ['is_certificate']
RX_IPADDR = GLOBAL_OBJ['rx_ipaddr']
TX_IPADDR = GLOBAL_OBJ['tx_ipaddr']
RANGE = GLOBAL_OBJ['range']
TIME_OK = GLOBAL_OBJ['time_ok']
SPEED = float(GLOBAL_OBJ['speed'])
NOISZE_STRENGTH_LOWER, NOISZE_STRENGTH_UPPER = parse_noise_strength()
CONSTANT_J = float(GLOBAL_OBJ['constant_j'])
LOCATION_OK = GLOBAL_OBJ['location_ok']
LAT = GLOBAL_OBJ['location'][0] # latitude
LNG = GLOBAL_OBJ['location'][1] # longitude
NONCE_OK = GLOBAL_OBJ['nonce_ok']
NONCE_EXPIRE_TIME = GLOBAL_OBJ['nonce_expire_time']
LOCAION_DELAY_PER_METER_LOWER, LOCAION_DELAY_PER_METER_UPPER = parse_array('location_delay_per_meter')
