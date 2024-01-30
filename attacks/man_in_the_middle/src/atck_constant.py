import yaml


def get_cfg_value():
    with open('cfg.yaml', 'r') as f:
        return yaml.safe_load(f)

GLOBAL_OBJ = get_cfg_value() 
NODE_NAME = GLOBAL_OBJ['name']
PORT = GLOBAL_OBJ['port']
BUFFER_SIZE = GLOBAL_OBJ['buffer_size']
RX_IPADDR = GLOBAL_OBJ['rx_ipaddr']
TX_IPPADDR_SENDER = GLOBAL_OBJ['tx_ipaddr_sender']
TX_IPADDR_IMPERSONATED = GLOBAL_OBJ['tx_ipaddr_impersonated']
ACTIVE_ATTACK = GLOBAL_OBJ['active_attack']
DELAY_TIME = GLOBAL_OBJ['delay_time']
IS_CERTIFICATE = False
TIME_OK = GLOBAL_OBJ['time_ok']
LOCATION_OK = GLOBAL_OBJ['location_ok']
LAT = GLOBAL_OBJ['location'][0] # latitude
LNG = GLOBAL_OBJ['location'][1] # longitude
