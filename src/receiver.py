from multiprocessing import Process, Lock
import socket
import json
import requests
from constant import *
import crypto # using our own crypto module # using our own crypto module
import utils
import time
import random


# Define the Receiver class as a child of the Process class
class Receiver(Process):

    # Initialize the Receiver object
    def __init__(self, node_name):
        self.node_name = node_name # Store the name of the receiver node
        self.name = f"{node_name} Receiver" # Set a unique name for this Receiver process
        super().__init__(name = self.name)
        self.lock = Lock() # Lock resources to prevent accessing from multiple threads at the same time
        self.neighbors = {} # Initialize an empty list to store neighbors
        self.sign_impl = crypto.CryptoStrategy(crypto.CryptoECC(node_name), 'ECC') # Create a cryptographic strategy for signing. In this case Elliptic Curve Cryptography (ECC)
        self.nonce_store = utils.InMemoryStore()

    # The run method is executed when the process starts
    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:  # Set up a socket for TCP communication
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Set socket option to allow reusing a local address when binding it.
            s.bind((RX_IPADDR, PORT)) # Bind the socket to the specified IP address and port
            print(f"{self.name} is listening on {RX_IPADDR}:{PORT}")
            s.listen() # Enable the socket to accept connections
            while True:
                # Accept a connection and start a new process to handle it
                conn, addr = s.accept()
                Process(target=self.handle_connection, args=(conn, addr)).start()

    # Method to authenticate received data
    def authenticate(self, verify_crypto, dict_data):
        verify_data = dict_data.copy()
        del verify_data['signature']  # Remove the signature from the data for verification

        # Verify the signature of the data using the cryptographic strategy
        if not verify_crypto.verify(str(verify_data), dict_data['signature']): # Verify if the signed data we received in dict_data is same as the actual data (i.e., proof of data integrity)
            print("authentication failed")
            return False # Data authentication failed
        return True # Data authentication succeeded

    # Method to check if the distance is within a specified range
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
            return False # node is out of range and is not a neighbor
        return True # node is in the range and is a neighbor

    # Method to handle a connection from a neighbor
    def handle_connection(self, conn, addr):
        gensk_ok = False
        with conn:
            print(f"{self.name} accept new connection from {addr}")
            start_time = None
            while True:
                # Receive data from the connection
                # or ends with an empty string if the connection is closed or there is an error.
                data = conn.recv(BUFFER_SIZE)
                # Break the loop if no data or 'exit' is received
                if not data or data.decode('utf-8') == 'exit':
                    break
                dict_data = json.loads(data.decode('utf-8')) # Decode the received data as JSON
                if dict_data['msg'] == 'hej': # if received a "hej" message
                    print(f"{self.name} received {dict_data['msg']} from {dict_data['node_name']}")
                    # Create a cryptographic strategy for the neighbor
                    neighbor_crypto = crypto.CryptoStrategy(crypto.CryptoECC(dict_data['node_name']), 'ECC')
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

                    # Authenticate the received data
                    if not self.authenticate(neighbor_crypto, dict_data):
                        print(f"{self.name} authentication failed from {dict_data['node_name']}")
                        break # Data authentication failed, exit the loop


                    # simulate noise
                    if TIME_OK:
                        delay_ms = random.uniform(NOISZE_STRENGTH_LOWER, NOISZE_STRENGTH_UPPER)
                        delay_s = delay_ms / 1000
                        print(f"{self.name} noise {delay_s} s from {dict_data['node_name']}")
                        time.sleep(delay_s)

                    # generate shared key (sk)
                    priv_key = self.sign_impl.export_priv_key() # the exported private key of the current node
                    eph_priv_key = self.sign_impl.export_eph_priv_key() # the exported ephemeral private key of the current node
                    neighbor_crypto.import_sk_fs(priv_key, eph_priv_key) #  import the private key (priv_key) and ephemeral private key (eph_priv_key) into the cryptographic strategy of the neighbor (neighbor_crypto).
                    if TIME_OK:
                        start_time = time.time_ns() # record the current time in nanoseconds
                    if NONCE_OK:
                        conn.sendall(self.build_init_msg(neighbor_crypto, dict_data['nonce_a']))  # Send an initialization message to the neighbor
                    else:
                        conn.sendall(self.build_init_msg(neighbor_crypto, None))
                    neighbor = {
                        'addr': addr[0]+":"+str(addr[1]),
                        'pk': pk,
                        'node_name': dict_data['node_name'],
                        'neighbor_crypto': neighbor_crypto,
                    }
                    self.lock.acquire() # control access to a shared resource i.e., neighbors dictionary
                    self.neighbors[neighbor['addr']] = neighbor # add or update the current neighbor's information against the key 'addr'
                    self.lock.release() # release the resource lock for others to use now as the critical operation is executed
                    gensk_ok = True # indicate that the shared key is successfully generated
                    print(f"{self.name} current neighbors: {self.neighbors}")
                     # Invoke a web request to add neighbor
                    self.invoke_web('POST', neighbor)

                else: # Handle messages other than 'hej' from neighbors
                    if not gensk_ok: # check if shared key is not generated
                        print(f"{self.name} received unexpected {dict_data} from {addr}")
                        break
                    if TIME_OK:
                        end_time = time.time_ns() # record the end time in nanoseconds
                        delta_t = (end_time - start_time) / float(1e9) # duration of time in seconds (from nano seconds)
                        tof =  ((SPEED * delta_t )/ 2.0) * CONSTANT_J
                        print(f"{self.name} time of flight is {tof} m and delta_t is {delta_t} s")
                        if tof > RANGE:
                            print(f"{self.name} delay/relay attack detected")
                            break

                     # Retrieve neighbor cryptographic information
                    self.lock.acquire() # lock shared resource i.e., neighbors dict
                    neighbor_crypto = self.neighbors[addr[0]+":"+str(addr[1])]['neighbor_crypto'] # retrieve the cryptographic information associated with a specific neighbor. addr[0] has IP concatenated with addr[1] which is port number with a : in-between.
                    self.lock.release() # release the resource

                    # Decrypt the received message using the shared key
                    ori_msg = neighbor_crypto.decrypt_sk(dict_data['msg'], dict_data['nonce'], dict_data['tag'])
                    ori_msg = ori_msg.replace("\'", "\"")
                    ori_msg = ori_msg.replace("None", "\"None\"")
                    print(f"{self.name} received {ori_msg} from {addr}")
                    # Parse the decrypted message as JSON
                    msg = json.loads(ori_msg)
                    if msg['msg'] == 'snd_packet':
                        # check nonce
                        if NONCE_OK:
                            nonce = msg['nonce_b']
                            print(f"{self.name} received nonce {nonce} from {msg['node_name']}")
                            if utils.compare_nonce(nonce) is True:
                                print(f"{self.name} received expired nonce from {msg['node_name']}")
                                break
                            if nonce in self.nonce_store:
                                print(f"{self.name} received repeated nonce from {msg['node_name']}")
                                break
                            # First come, store the nonce
                            self.nonce_store.add(nonce)
                            # TODO: use a seprate thread to remove expired nonce
                            self.nonce_store.stabliize()

                        # Check if the distance is within range (if specified)
                        if LOCATION_OK and (not self.check_distance(msg)):
                            print(f"{self.name} distance is out of range from {msg['node_name']}")
                            break # if out of range, exit the loop

                        print(f"{self.name} received {msg['msg']} payload {msg['payload']} from {msg['node_name']}")

                        # Send a response message to the neighbor
                        payload = {"msg": f"hello, I am {self.node_name}", "mac": utils.get_interface_mac(RX_IPADDR)}
                        conn.sendall(self.build_msg(neighbor_crypto, "snd_packet", payload))

        # Print a message indicating the connection is closed
        print(f"{self.name} connection from {addr} closed")
        # If shared key generation was successful
        if gensk_ok:
            self.lock.acquire()
            neighbor = self.neighbors[addr[0]+":"+str(addr[1])]
            # Remove the neighbor from the list of neighbors
            del self.neighbors[addr[0]+":"+str(addr[1])]
            # Invoke a web request to remove the neighbor
            self.invoke_web('DELETE', neighbor)
            self.lock.release()
        # Print the current neighbors
        print(f"{self.name} current neighbors: {self.neighbors}")
        
    def build_init_msg(self, neighbor_crypto, nonce_a):
        # Create an initialization message for a neighbor
        if IS_CERTIFICATE:
            cert = self.sign_impl.export_certificate()
            msg = {
                "msg": "hejhej",
                "node_name": self.node_name,
                "cert": cert
                }
        else:
            msg = {
                "msg": "hejhej",
                "node_name": self.node_name,
                "pk": self.sign_impl.export_pk()
                }
        # Generate a Hash-based Message Authentication Code (HMAC) using the neighbor's cryptographic strategy
        msg["hmac"] = neighbor_crypto.generate_mac(b"hello")
        msg['eph_pk'] = self.sign_impl.export_eph_pk() # Sender's ephemeral public key
        if NONCE_OK: 
            msg['nonce_a'] = nonce_a
            msg['nonce_b'] = utils.generate_nonce()
        # Sign the message using the sender's private key
        msg["signature"] = self.sign_impl.sign(str(msg))
        # Convert the message to JSON format and encode it as bytes
        json_msg = json.dumps(msg)
        return json_msg.encode('utf-8')

    # Method to  build a message for secure communication with a neighbor
    def build_msg(self, neighbor_crypto, msg, payload):
        ori_msg = {"msg": msg, "payload": payload, "node_name": self.node_name}

        # Location information
        if LOCATION_OK:
            ori_msg['lat'] = LAT
            ori_msg['lng'] = LNG

        # encrypt-then-sign
        # Encrypt the message using the neighbor's shared key
        ct, nonce, tag = neighbor_crypto.encrypt_sk(str(ori_msg))
        # Construct the final message with encrypted content
        msg = {"msg": ct, "nonce": nonce, "tag": tag}
        # Convert the message to JSON format and encode it as bytes
        json_msg = json.dumps(msg)
        return json_msg.encode('utf-8')

    # Method to handle API requests
    def invoke_web(self, method, data):
        url = f'http://{RX_IPADDR}:{WEB_PORT}/neighbors'
        headers = {'Content-type': 'application/json'}
        resp = None

        # Choose the appropriate HTTP method based on the input
        if method == 'GET':
            resp = requests.get(url, headers=headers)
        elif method == 'POST':
            resp = requests.post(url, data=json.dumps(data), headers=headers)
        elif method == 'DELETE':
            resp = requests.delete(url, data=json.dumps(data), headers=headers)
        else :
            # Raise an exception for an invalid method
            raise Exception("Invalid method")

         # Check the response status code and print a corresponding message
        if resp.status_code == 200:
            print(f"{self.name} {method} neighbor {data['node_name']} successfully")
        else:
            print(f"{self.name} {method} neighbor {data['node_name']} failed code {resp.status_code}")

