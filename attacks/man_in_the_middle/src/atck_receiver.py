from multiprocessing import Process, Lock
import socket
import json
from atck_constant import *
import time
import sys
import crypto

class AtckReceiver(Process):
    def __init__(self, node_name):
        self.node_name = node_name
        self.name = f"{node_name} Receiver"
        super().__init__(name = self.name)
        self.lock = Lock()
        self.neighbors = {}
        self.sign_impl = crypto.CryptoStrategy(crypto.CryptoRSA(node_name), 'RSA')
    
    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Set socket option to allow reusing a local address when binding it.
            s.bind((RX_IPADDR, PORT))
            print(f"{self.name} is listening on {RX_IPADDR}:{PORT}")
            s.listen()
            while True:
                conn, addr = s.accept()
                Process(target=self.handle_connection, args=(conn, addr)).start() 

    def handle_connection(self, conn, addr):
        with conn:
            print(f"{self.name} accept new connection from {addr}")
            while True:
                # block to receive data 
                # or ends with an empty string if the connection is closed or there is an error.
                data = conn.recv(BUFFER_SIZE)
                if not data or data.decode('utf-8') == 'exit':
                    break
                dict_data = json.loads(data.decode('utf-8')) 
                # first message
                if dict_data['msg'] == 'hej':
                    print(f"{self.name} received {dict_data['msg']} from {dict_data['node_name']}")
                    if dict_data['node_name'] == 'vm2':
                        print(f"{self.name} ignored {dict_data['msg']} from {dict_data['node_name']}")
                        return

                    # open connection to the impersonated
                    self.connect_to_impersonated()
                    # delay on purpose
                    time.sleep(DELAY_TIME/1000)
                    conn.sendall(self.build_init_msg(dict_data))
                else:
                    conn.sendall(self.build_msg(dict_data))
        print(f"{self.name} connection from {addr} closed")

        time.sleep(5)
        # close connection with impersonated because conn with VM1 is also closed
        self.connection_impl.close()

    def build_init_msg(self, dict_data):
        if not ACTIVE_ATTACK:
            # realy message
            data = json.dumps(dict_data)
            data = data.encode('utf-8') 
            received_message = self.send_message_to_impersonated(data)
            return received_message

        # modify message
        neighbor_crypto = crypto.CryptoStrategy(crypto.CryptoRSA(dict_data['node_name']), 'RSA')
        neighbor_crypto.import_pk(dict_data['pk'])
        dict_data['pk'] = self.sign_impl.export_pk()
        del dict_data['signature']
        dict_data['signature'] = self.sign_impl.sign(str(dict_data))
        data = json.dumps(dict_data)
        print(f"adv is sending {dict_data} to {dict_data['node_name']}")
        data = data.encode('utf-8')
        received_message =  self.send_message_to_impersonated(data)
        dict_msg = json.loads(received_message.decode('utf-8'))

        # get sk
        sk = self.sign_impl.decrypt(dict_msg['sk'])
        self.sign_impl.import_sk(sk)
        sk_encrypted = neighbor_crypto.encrypt(sk)
        dict_msg['sk'] = sk_encrypted
        dict_msg['pk'] = self.sign_impl.export_pk() 

        # generate new msg
        del dict_msg['signature']
        dict_msg['signature'] = self.sign_impl.sign(str(dict_msg))
        data = json.dumps(dict_msg)
        print(f"adv is sending {data} to {data['node_name']}")
        data = data.encode('utf-8')
        return data

        
    def build_msg(self, dict_data):        # open connection to the impersonated
        if not ACTIVE_ATTACK:
            # realy message
            data = json.dumps(dict_data)
            data = data.encode('utf-8') 
            received_message = self.send_message_to_impersonated(data)
            return received_message

        # print message, attacker can see the message
        # ori_msg = self.sign_impl.decrypt_sk(dict_data['msg'], dict_data['iv'], None) 
        # ori_msg = ori_msg.replace("\'", "\"")
        # msg = json.loads(ori_msg)
        # print(f"{self.name} received {msg['msg']} from {msg['node_name']}")

        del dict_data['signature']
        dict_data['signature'] = self.sign_impl.sign(str(dict_data))
        data = json.dumps(dict_data)
        data = data.encode('utf-8')
        received_message =  self.send_message_to_impersonated(data)
        dict_msg = json.loads(received_message.decode('utf-8'))
        del dict_msg['signature']
        dict_msg['signature'] = self.sign_impl.sign(str(dict_msg))
        data = json.dumps(dict_msg)
        data = data.encode('utf-8')
        return data

    
    def connect_to_impersonated(self):
        time.sleep(1) # in case the impersonated is not ready yet
        self.connection_impl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection_impl.connect_ex((TX_IPADDR_IMPERSONATED, PORT))
    
    def send_message_to_impersonated(self, msg):
        
        # send message to impersonated
        self.connection_impl.sendall(msg)

        # Wait for response
        data = self.connection_impl.recv(BUFFER_SIZE)

        if not data or data.decode('utf-8') == 'exit':
            return None

        return data
