from multiprocessing import Process
import socket
import json
from constant import *
import time
import errno
import crypto

class Transmitter(Process):
    def __init__(self, node_name):
        self.node_name = node_name
        self.name = f"{node_name} Transmitter"
        super().__init__(name=self.name)
        self.neighbor = None
        self.sign_impl = crypto.CryptoStrategy(crypto.CryptoRSA(node_name), 'RSA')

    def authenticate(self, verify_crypto, dict_data):
        verify_data = dict_data.copy()
        del verify_data['signature']
        if not verify_crypto.verify(str(verify_data), dict_data['signature']):
            print("authentication failed")
            return False
        return True
    
    def run(self):
        count = 0
        s = None
        for _ in range(5):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # assume we know the ip address of the receiver, one tx can only connect to one rx
            # but practically we need to broadcast to find receivers
            # tx can connect to multiple rxs
            print(f"{self.name} connecting to {TX_IPADDR}:{PORT} {count} times")
            err = s.connect_ex((TX_IPADDR, PORT))
            count += 1
            if err == 0:
                break
            print(f"{self.name} connection err: {errno.errorcode[err]}")
            s.close()
            time.sleep(5)

        if count == 5:
            return
        gensk_ok = False
        while True:
            if not gensk_ok:
                s.sendall(self.build_init_msg())
            else:
                s.sendall(self.build_msg("snd_packet", {"msg": f"hello, I am {self.node_name}"}))
            data = s.recv(BUFFER_SIZE)
            if not data or data.decode('utf-8') == 'exit':
                break
            dict_data = json.loads(data.decode('utf-8'))
            if dict_data['msg'] == 'hejhej':
                print(f"{self.name} received {dict_data['msg']} from {dict_data['node_name']}")
                neighbor_crypto = crypto.CryptoStrategy(crypto.CryptoRSA(dict_data['node_name']), 'RSA')
                neighbor_crypto.import_pk(dict_data['pk'])
                if not self.authenticate(neighbor_crypto,dict_data):
                    break
                sk = self.sign_impl.decrypt(dict_data['sk'])
                neighbor_crypto.import_sk(sk)
                neighbor = {
                    'addr': TX_IPADDR+":"+str(PORT),
                    'pk': dict_data['pk'],
                    'node_name': dict_data['node_name'],
                    'neighbor_crypto': neighbor_crypto,
                }
                self.neighbor = neighbor
                gensk_ok = True
                time.sleep(5)
            else:
                if not gensk_ok:
                    print(f"{self.name} received unexpected {dict_data} from {TX_IPADDR}")
                    break
                neighbor_crypto = self.neighbor['neighbor_crypto']
                if not self.authenticate(neighbor_crypto, dict_data):
                    break
                ori_msg = neighbor_crypto.decrypt_sk(dict_data['msg'], dict_data['iv'], None)
                ori_msg = ori_msg.replace("\'", "\"")
                msg = json.loads(ori_msg)
                if msg['msg'] == 'snd_packet':
                    print(f"{self.name} received {msg['msg']} payload {msg['payload']} from {msg['node_name']}")
                    # TODO: handle snd_packet
                    time.sleep(100)
                    break
        s.close()

    def build_init_msg(self):
        msg = {"msg": "hej", "node_name": self.node_name, "pk": self.sign_impl.export_pk()}
        msg["signature"] = self.sign_impl.sign(str(msg))
        json_msg = json.dumps(msg)
        return json_msg.encode('utf-8')
    
    def build_msg(self, msg, payload):
        ori_msg = {"msg": msg, "payload": payload, "node_name": self.node_name}
        # encrypt-then-sign
        ct, iv = self.neighbor['neighbor_crypto'].encrypt_sk(str(ori_msg))
        msg = {"msg": ct, "iv": iv}
        msg["signature"] = self.sign_impl.sign(str(msg))
        json_msg = json.dumps(msg)
        return json_msg.encode('utf-8')

