from multiprocessing import Process, Lock
import socket
import json
from constant import *
import crypto

# Define the Receiver class as a child of the Process class
class Receiver(Process):

    # Initialize the Receiver object
    def __init__(self, node_name):
        self.node_name = node_name # Store the name of the receiver node
        self.name = f"{node_name} Receiver" # Set a unique name for this Receiver process
        super().__init__(name = self.name)
        self.lock = Lock() # Lock resources to prevent accessing from multiple threads at the same time
        self.neighbors = {} # Initialize an empty list to store neighbors
        self.sign_impl = crypto.CryptoStrategy(crypto.CryptoRSA(node_name), 'RSA') # Create a cryptographic strategy for signing. In this case RSA.
    
    # The run method is executed when the process starts
    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: # Set up a socket for TCP communication
            s.bind((RX_IPADDR, PORT)) # Bind the socket to the specified IP address and port
            s.listen() # Enable the socket to accept connections
            while True:
                # Accept a connection and start a new process to handle it
                conn, addr = s.accept()
                Process(target=self.handle_connection, args=(conn, addr)).start() 

    # Method to authenticate received data
    def authenticate(self, verify_crypto, dict_data):
        verify_data = dict_data.copy()
        del verify_data['signature'] # Remove the signature from the data for verification
        
        # Verify the signature of the data using the cryptographic strategy
        if not verify_crypto.verify(str(verify_data), dict_data['signature']):
            print("authentication failed")
            return False # Data authentication failed
        return True # Data authentication succeeded

    # Method to handle a connection from a neighbor
    def handle_connection(self, conn, addr):
        gensk_ok = False
        with conn:
            print(f"{self.name} accept new connection from {addr}")
            while True:
                # Receive data from the connectio 
                # or ends with an empty string if the connection is closed or there is an error.
                data = conn.recv(BUFFER_SIZE)
                # Break the loop if no data or 'exit' is received
                if not data or data.decode('utf-8') == 'exit':
                    break
                dict_data = json.loads(data.decode('utf-8')) # Decode the received data as JSON
                if dict_data['msg'] == 'hej': # if received a "hej" message
                    print(f"{self.name} received {dict_data['msg']} from {dict_data['node_name']}")
                    # Create a cryptographic strategy for the neighbor
                    neighbor_crypto = crypto.CryptoStrategy(crypto.CryptoRSA(dict_data['node_name']), 'RSA')
                    neighbor_crypto.import_pk(dict_data['pk'])
                    
                    # Authenticate the received data
                    if not self.authenticate(neighbor_crypto, dict_data):
                        break # Data authentication failed, exit the loop

                    conn.sendall(self.build_init_msg(neighbor_crypto)) # Send an initialization message to the neighbor
                    neighbor = {
                        'addr': addr[0]+":"+str(addr[1]),
                        'pk': dict_data['pk'],
                        'node_name': dict_data['node_name'],
                        'neighbor_crypto': neighbor_crypto,
                    }
                    self.lock.acquire() # control access to a shared resource i.e., neighbors dictionary
                    self.neighbors[neighbor['addr']] = neighbor # add or update the current neighbor's information against the key 'addr'
                    self.lock.release() # release the resource lock for others to use now as the critical operation is executed
                    gensk_ok = True # indicate that the shared key is successfully generated
                    print(f"{self.name} current neighbors: {self.neighbors}")
                else: # Handle messages other than 'hej' from neighbors
                    if not gensk_ok: # check if shared key is not generated
                        print(f"{self.name} received unexpected {dict_data} from {addr}")
                        break

                     # Retrieve neighbor cryptographic information
                    self.lock.acquire() # lock shared resource i.e., neighbors dict
                    neighbor_crypto = self.neighbors[addr[0]+":"+str(addr[1])]['neighbor_crypto'] # retrieve the cryptographic information associated with a specific neighbor. addr[0] has IP concatenated with addr[1] which is port number with a : in-between.
                    self.lock.release() # release the resource
                    if not self.authenticate(neighbor_crypto, dict_data):
                        break

                    # Decrypt the received message using the shared key
                    ori_msg = neighbor_crypto.decrypt_sk(dict_data['msg'], dict_data['iv'], None)
                    ori_msg = ori_msg.replace("\'", "\"")
                    # Parse the decrypted message as JSON
                    msg = json.loads(ori_msg)
                    if msg['msg'] == 'snd_packet':
                        print(f"{self.name} received {msg['msg']} payload {msg['payload']} from {msg['node_name']}")
                        # Send a response message to the neighbor
                        conn.sendall(self.build_msg(neighbor_crypto, "snd_packet", {"msg": f"hello, I am {self.node_name}"}))
        # Print a message indicating the connection is closed
        print(f"{self.name} connection from {addr} closed")

        # If shared key generation was successful
        if gensk_ok:
            self.lock.acquire()
            # Remove the neighbor from the list of neighbors
            del self.neighbors[addr[0]+":"+str(addr[1])]
            self.lock.release()
        # Print the current neighbors
        print(f"{self.name} current neighbors: {self.neighbors}")
    
    # Method to prepare initialization message for the nighbor
    def build_init_msg(self, neighbor_crypto):
        # Create an initialization message for a neighbor
        msg = {"msg": "hejhej", "node_name": self.node_name, "pk": self.sign_impl.export_pk()}

        # Generate the shared key using neighbor's cryptography strategy
        sk = neighbor_crypto.export_sk()
        # encrypt the shared key and add it in the message
        msg["sk"] = neighbor_crypto.encrypt(sk)

        # Sign the message using the sender's private key
        msg["signature"] = self.sign_impl.sign(str(msg))
        # Convert the message to JSON format and encode it as bytes
        json_msg = json.dumps(msg)
        return json_msg.encode('utf-8')

    # Method to  build a message for secure communication with a neighbor
    def build_msg(self, neighbor_crypto, msg, payload):
        ori_msg = {"msg": msg, "payload": payload, "node_name": self.node_name}
        # encrypt-then-sign
        # Encrypt the message using the neighbor's shared key
        ct, iv = neighbor_crypto.encrypt_sk(str(ori_msg))
        # Construct the final message with encrypted content
        msg = {"msg": ct, "iv": iv}
        msg["signature"] = self.sign_impl.sign(str(msg))
        # Convert the message to JSON format and encode it as bytes
        json_msg = json.dumps(msg)
        return json_msg.encode('utf-8')
