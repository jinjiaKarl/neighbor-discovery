import math
import requests
import json, hashlib, uuid, time
from datetime import datetime, timedelta
from getmac import get_mac_address
from Crypto.PublicKey import ECC
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from atck_constant import *

# Calculate Euclidean distance between two locations
def calculate_distance(lat1, lng1, lat2, lng2):
    """
    Calculate the distance between two locations.

    For simplicity, we use the Euclidean distance even though it is not suitable

    Perfectly, Haversine formula should be used.
    """

    distance = math.sqrt((float(lat1) - float(lat2))**2 + (float(lng1) - float(lng2))**2)

    return distance


# Get MAC address of a given IP address
def get_interface_mac(ip_address):
    mac = get_mac_address(ip=ip_address) # imported  from getmac library and used to retrieve MAC address of a network interface associated with a given IP address.
    if mac is None:
        # assume the interface is eth0
        # TODO: get the interface name from the ip address
        return get_mac_address(interface="eth0")
    return mac

# Generate ephemeral ECC key pair
def generate_ephemeral_key():
    # Generate a private key using the desired elliptic curve
    priv_key = ECC.generate(curve='ed25519')
     # Derive the corresponding public key from the private key
    pub_key = priv_key.public_key()
    # Return both the private and public keys as a tuple
    return priv_key, pub_key

# Generate ECC Certificate Signing Request (CSR) with a given common name
def generate_ecc_csr(common_name: str):
    # Define the path for the private key file
    key_path = f"key_pairs/{common_name}_new_ecc_private.pem"

    # Check if the private key file already exists
    if os.path.exists(key_path):
        print(f"Key {key_path} already exists")
        return # Return if the key already exists
    
    # Generate a new Ed25519 private key
    private_key = Ed25519PrivateKey.generate()

    # Serialize the private key to PEM format without encryption
    key_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM, # Output format is PEM
        format=serialization.PrivateFormat.PKCS8, # Private key format is PKCS#8
        encryption_algorithm=serialization.NoEncryption()  # No encryption is applied
    )

    # Store the private key in a file
    store_file(key_data, key_path)

    # Build the Certificate Signing Request (CSR)
    builder = x509.CertificateSigningRequestBuilder()
    # Set the subject name of the CSR based on the common name
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
    # Add a basic constraints extension to the CSR
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )

    # Sign the CSR with the private key
    request = builder.sign(
        private_key=private_key, algorithm=None
    )
    # Define the path for the CSR file
    csr_path = f"key_pairs/{common_name}_ecc_csr.pem"
    # Serialize the CSR to PEM format
    csr_data = request.public_bytes(serialization.Encoding.PEM)
    # Store the CSR in a file
    store_file(csr_data, csr_path)
    return csr_data

# URL for the Certificate Authority (CA)
ca_url = f'http://127.0.0.1:9999'

# Generate ECC certificate
def generate_certificate(common_name: str):
    # Define the file path for the certificate
    cert_path = f"key_pairs/{common_name}_ecc.crt"

    # Check if the certificate file already exists
    if os.path.exists(cert_path):
        print(f"Certificate {cert_path} already exists")
        return # Return if the certificate already exists
    
    # Generate a Certificate Signing Request (CSR) using ECC
    csr_data = generate_ecc_csr(common_name)
    # Prepare headers for the certificate request
    headers = {'Content-type': 'application/json'}
    # Prepare data for the certificate request
    data = {"csr": csr_data.decode("utf-8")}
    # Send a POST request to the Certificate Authority (CA) to issue the certificate
    resp = requests.post(f"{ca_url}/issue", data=json.dumps(data), headers=headers)
    
    # Check if the request was successful (status code 200)
    if resp.status_code == 200:
        resp_data = resp.json() # Parse the response data as JSON
        cert_data = resp_data['cert'].encode("utf-8") # Extract the certificate data from the response and encode it
        store_file(cert_data, cert_path) # Store the certificate data in a file
    else:
        raise Exception("Get certificate failed") # Raise an exception if the certificate request fails
    

# Check the validity of a certificate with the Certificate Authority (CA)
def check_certificate(cert_data: bytes, common_name: str):
    # Prepare data for the certificate check request  
    data = {"cert": cert_data.decode("utf-8")}

    # Set headers for the certificate check request
    headers = {'Content-type': 'application/json'}

    # Send a POST request to the Certificate Authority (CA) to check the certificate
    resp = requests.post(f"{ca_url}/check", data=json.dumps(data), headers=headers)
    
    # Check if the request was successful (status code 200)
    if resp.status_code == 200:
        resp_data = resp.json() # Parse the response data as JSON
        if resp_data['status'] is False: # Check if the certificate status is False in the response
            return False
        
        # Check if the common name matches the expected value
        cert = x509.load_pem_x509_certificate(cert_data)
        if cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != common_name:
            return False
        
        # Return True if the certificate is valid
        return True
    else:
        raise Exception("Check certificate failed") # Raise an exception if the certificate check request fails

# Load an X.509 certificate from a file path
def load_cert(path: str) -> x509.Certificate:
    # Open the specified file path in read mode
    with open(path, "r") as f:
        # Read the content of the file and encode it to UTF-8
        # Load the PEM-encoded X.509 certificate from the file content
        cert = x509.load_pem_x509_certificate(f.read().encode("utf-8"))
    return cert # Return the loaded X.509 certificate

# Load an X.509 certificate from bytes
def load_cert_from_bytes(cert_data: bytes) -> x509.Certificate:
    # Load the PEM-encoded X.509 certificate from the provided bytes
    cert = x509.load_pem_x509_certificate(cert_data)
    return cert # Return the loaded X.509 certificate

# Extract and return the public key from an X.509 certificate as a string
def get_public_key_from_cert(cert) -> str:
    # Retrieve the public key from the certificate and encode it as PEM format
    pk = cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return pk # Return the public key as a string

# Store binary data in a file, optionally overwriting existing content
def store_file(data: bytes, path: str, force: bool = False) -> bool:
    try:
        # Open the specified file path in write mode
        with open(path, "w") as f:
            f.write(data.decode("utf-8"))

    except OSError as err:
        raise err # Raise an exception if there is an OS-related error

    return True # Indicate successful file storage

# Generate a secure nonce combining a random UUID and a timestamp
def generate_nonce():
    # Generate a random UUID and convert it to a hexadecimal string
    nonce = uuid.uuid4().hex
    # Get the current timestamp as an integer and convert it to a string
    timestamp = str(int(time.time()))
    # Concatenate the nonce and timestamp, encode as UTF-8, hash using SHA-256, and return the hexadecimal digest
    return nonce + timestamp

def compare_nonce(nonce):
    current = datetime.fromtimestamp(time.time())
    # chech if nonce is expired
    if current - datetime.fromtimestamp(int(nonce[32:])) > timedelta(seconds=NONCE_EXPIRE_TIME):
        return True
    return False

# In-memory data store class for quick and simple data storage
class InMemoryStore:
    def __init__(self):
        # Initialize an empty list to store data
        self.store = []
    
    def add(self, data):
        # Add the provided data to the in-memory store
        self.store.append(data)
    
    def __contains__(self, data):
        # Check if the provided data is present in the in-memory store
        return data in self.store
    
    def stabliize(self):
        # delete 2 minutes old nonce
        current = datetime.fromtimestamp(time.time())
        self.store = [data for data in self.store if current - datetime.fromtimestamp(int(data[32:])) < timedelta(seconds=NONCE_EXPIRE_TIME)]

# deprecated
# Create and define access points with signal attenuation, location, and reference information 
def creat_ap(x, y, name):
    # Create an access point dictionary with specific values for "vm1" and default values otherwise
    if name == "vm1":
        ap = {
                "signalAttenuation": 3,
                "location": {
                    "x": x,
                    "y": y,
                },
                "reference": {
                    "distance": 80,
                    "signal": -50
                },
                "name": name
            }
    else:
        ap = {
                "signalAttenuation": 4,
                "location": {
                    "x": x,
                    "y": y,
                },
                "reference": {
                    "distance": 8,
                    "signal": -41
                },
                "name": name
            }
    return ap

ap1 = {
        "signalAttenuation": 3,
        "location": {
            "x": 1,
            "y": 1
        },
        "reference": {
            "distance": 4,
            "signal": -50
        },
        "name": "KTHOPEN"
    }

ap2 = {
        "signalAttenuation": 4,
        "location": {
            "x": 1,
            "y": 7
        },
        "reference": {
            "distance": 3,
            "signal": -41
        },
        "name": "eduroam"
    }

ap3 = {
        "signalAttenuation": 4,
        "location": {
            "x": 5,
            "y": 7
        },
        "reference": {
            "distance": 7,
            "signal": -70
        },
        "name": "secclo"
    }
# List of access points and an RSSI_Localizer object for signal strength localization
accessPoints = [ ap1, ap2, ap3]

