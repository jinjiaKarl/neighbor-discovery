from multiprocessing import Process
import socket
import json
from constant import *
import time, random
import errno
import crypto  # using our own crypto module
import utils

# Define the Transmitter class as a child of the Process class
class Transmitter(Process):

    # Initialize the Transmitter object
    def __init__(self, node_name):
        self.node_name = node_name  # Store the name of the transmitter node
        self.name = f"{node_name} Transmitter"  # Set a unique name for this Transmitter process
        super().__init__(name=self.name)
        self.neighbor = None  # Initialize neighbor information to None
        self.sign_impl = crypto.CryptoStrategy(crypto.CryptoECC(node_name), 'ECC')  # Create a cryptographic strategy for signing
        self.nonce_store = utils.InMemoryStore()
        self.nonce_received = 0;

    def authenticate(self, verify_crypto, dict_data):
        # Authenticate received data using a cryptographic strategy
        verify_data = dict_data.copy()
        del verify_data['signature']  # Remove the signature from the data for verification
        if not verify_crypto.verify(str(verify_data), dict_data['signature']):
            print("authentication failed")
            return False  # Data authentication failed
        return True  # Data authentication succeeded

    def check_distance(self, dict_data):
        """
        If the distance is out of a range, it is not considered as a neighbor.
        """
        dis = utils.calculate_distance(dict_data['lat'], dict_data['lng'], LAT, LNG)
        delay_ms = random.uniform(LOCAION_DELAY_PER_METER_LOWER, NOISZE_STRENGTH_UPPER)
        delay_s = delay_ms / 1000
        time.sleep(delay_s * dis) # simulate the delay
        print(f"{self.name} distance from {dict_data['node_name']} is {dis} m, delay is {delay_s * dis} s")
        if dis > RANGE:
            return False
        return True

    def run(self):
        count = 0
        s = None
        # Attempt to establish a connection to the receiver (TX_IPADDR and PORT)
        for _ in range(5):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # assume we know the ip address of the receiver, one tx can only connect to one rx
            # but practically we need to broadcast to find receivers
            # tx can connect to multiple rxs
            print(f"{self.name} connecting to {TX_IPADDR}:{PORT} {count} times")
            err = s.connect_ex((TX_IPADDR, PORT))  # Attempt to connect to the specified IP address and port
            count += 1
            if err == 0:
                break
            print(f"{self.name} connection err: {errno.errorcode[err]}")
            s.close()
            time.sleep(5)  # Wait for 5 seconds before retrying

        if count == 5:
            return # if there have been 5 attempts means that the connection was unsuccessful

        gensk_ok = False
        start_time = None
        while True:
            if not gensk_ok:
                if TIME_OK:
                    start_time = time.time_ns() # in nanoseconds
                s.sendall(self.build_init_msg())  # Send an initialization message to the receiver
            else:
                payload = {"msg": f"hello, I am {self.node_name}" ,"mac": utils.get_interface_mac(RX_IPADDR)}
                s.sendall(self.build_msg("snd_packet",payload))  # Send a message with a payload to the receiver
            data = s.recv(BUFFER_SIZE)

            if not data or data.decode('utf-8') == 'exit':
                break  # Exit the loop if there is no data or an exit command is received

            dict_data = json.loads(data.decode('utf-8'))

            if dict_data['msg'] == 'hejhej': # if received a "hejhej" message
                print(f"{self.name} received {dict_data['msg']} from {dict_data['node_name']} ")

                neighbor_crypto = crypto.CryptoStrategy(crypto.CryptoECC(dict_data['node_name']), 'ECC') # QUESTION, shouldn't it be a variable and not a string???
                pk = None
                if IS_CERTIFICATE:
                    cert_data = dict_data['cert']
                    cert_data = cert_data.encode('utf-8')
                    # check certificate
                    if utils.check_certificate(cert_data, dict_data['node_name']) is False:
                        print(f"{self.name} received invalid certificate from {TX_IPADDR}")
                        break
                    cert = utils.load_cert_from_bytes(cert_data)
                    pk = utils.get_public_key_from_cert(cert)
                else:
                    pk = dict_data['pk']
                neighbor_crypto.import_pk(pk)
                neighbor_crypto.import_eph_pk(dict_data['eph_pk'])

                if not self.authenticate(neighbor_crypto, dict_data):
                    break  # Data authentication failed, exit the loop

                # check if there is relay attack
                if TIME_OK:
                    end_time = time.time_ns()
                    delta_t = (end_time - start_time) / float(1e9)
                    tof =  ((SPEED * delta_t) / 2.0) * CONSTANT_J
                    print(f"{self.name} time of flight is {tof} m and delta_t is {delta_t} s")
                    if tof > RANGE:
                        print(f"{self.name} delay/relay attack detected")
                        break

                # check nonce
                if NONCE_OK:
                    nonce = dict_data['nonce_a']
                    print(f"{self.name} received nonce {nonce} from {dict_data['node_name']}")
                    if utils.compare_nonce(nonce) is True:
                        print(f"{self.name} received expired nonce from {dict_data['node_name']}")
                        break
                    if nonce in self.nonce_store:
                        print(f"{self.name} received repeated nonce from {dict_data['node_name']}")
                        break
                    self.nonce_store.add(nonce)
                    self.nonce_store.stabliize()

                    self.nonce_received = dict_data['nonce_b']

                # Generate a shared secret key
                priv_key = self.sign_impl.export_priv_key()
                eph_priv_key = self.sign_impl.export_eph_priv_key()
                neighbor_crypto.import_sk_fs(priv_key, eph_priv_key)

                if dict_data['hmac'] != neighbor_crypto.generate_mac(b"hello"):
                    print(f"{self.name} compute non-matched shared key from {TX_IPADDR}")
                    break  # Shared key computation failed, exit the loop

                # Store neighbor information
                neighbor = {
                    'addr': TX_IPADDR + ":" + str(PORT),
                    'pk': pk,
                    'node_name': dict_data['node_name'],
                    'neighbor_crypto': neighbor_crypto,
                }
                # upadte neighbors
                self.neighbor = neighbor
                gensk_ok = True
            else:
                if not gensk_ok:
                    print(f"{self.name} received unexpected {dict_data} from {TX_IPADDR}")
                    break  # Unexpected data received, exit the loop

                neighbor_crypto = self.neighbor['neighbor_crypto']
                ori_msg = neighbor_crypto.decrypt_sk(dict_data['msg'], dict_data['nonce'], dict_data['tag'])
                ori_msg = ori_msg.replace("\'", "\"")  # Replace single quotes with double quotes for JSON
                ori_msg = ori_msg.replace("None", "\"None\"")
                msg = json.loads(ori_msg)

                if msg['msg'] == 'snd_packet':
                    if LOCATION_OK and (not self.check_distance(msg)):
                        print(f"{self.name} distance is out of range from {msg['node_name']}")
                        break
                    if LOCATION_OK:  
                        print(f"{self.name} received {msg['msg']} payload {msg['payload']} lag {msg['lat']} lng {msg['lng']} from {msg['node_name']}")
                    else:
                        print(f"{self.name} received {msg['msg']} payload {msg['payload']} from {msg['node_name']}")
                    # TODO: handle snd_packet
                    time.sleep(100)
                    break  # Exit the loop

        # closing the socket
        s.close()

    # Build an initialization message
    def build_init_msg(self):
        if IS_CERTIFICATE:
            cert = self.sign_impl.export_certificate()
            msg = {"msg": "hej", "node_name": self.node_name, "cert": cert}
        else:
            msg = {"msg": "hej", "node_name": self.node_name, "pk": self.sign_impl.export_pk()}
        msg['eph_pk'] = self.sign_impl.export_eph_pk()
        # nonce: guarantee that authentication is fresh
        if NONCE_OK:
            msg['nonce_a'] = utils.generate_nonce()
        msg["signature"] = self.sign_impl.sign(str(msg))
        json_msg = json.dumps(msg)
        return json_msg.encode('utf-8')

    # Build a message with the provided message type and payload
    def build_msg(self, msg, payload):
        ori_msg = {
            "msg": msg,
            "payload": payload,
            "node_name": self.node_name
        }
        if NONCE_OK:
            ori_msg['nonce_b'] = self.nonce_received

        # location
        if LOCATION_OK:
            ori_msg['lat'] = LAT
            ori_msg['lng'] = LNG

        # Encrypt the message, generate a nonce, and tag
        ct, nonce, tag = self.neighbor['neighbor_crypto'].encrypt_sk(str(ori_msg))
        msg = {"msg": ct, "nonce": nonce, "tag": tag}
        json_msg = json.dumps(msg)
        return json_msg.encode('utf-8') # encoding the message
