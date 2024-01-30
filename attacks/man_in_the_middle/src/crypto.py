from abc import ABCMeta, abstractmethod
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pkcs1_15, eddsa
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import HMAC, SHA256, SHAKE128
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.DH import key_agreement
from cryptography.hazmat.primitives import serialization
from base64 import b64encode, b64decode
import utils
from atck_constant import *


class CryptoImpl(metaclass=ABCMeta):
    @abstractmethod
    def sign(self, msg):
        pass
    @abstractmethod
    def verify(self, msg, signature):
        pass
    @abstractmethod
    def export_certificate(self):
        pass
    @abstractmethod
    def export_eph_pk(self):
        pass
    @abstractmethod
    def export_priv_key(self):
        pass
    @abstractmethod
    def export_pk(self):
        pass
    @abstractmethod
    def import_pk(self, pk):
        pass
    @abstractmethod
    def import_eph_pk(self,pk):
        pass
    @abstractmethod
    def export_eph_priv_key(self):
        pass
    @abstractmethod
    def export_sk(self):
        pass
    @abstractmethod
    def import_sk(self, sk):
        pass
    @abstractmethod
    def import_sk_fs(self, priv_key, eph_priv_key):
        pass
    @abstractmethod
    def encrypt(self, msg):
        pass
    @abstractmethod
    def decrypt(self, msg):
        pass
    @abstractmethod
    def encrypt_sk(self, msg):
        pass
    @abstractmethod
    def decrypt_sk(self, msg, iv, tag):
        pass
    @abstractmethod
    def generate_mac(self, msg):
        pass


class CryptoRSA(CryptoImpl):
    def __init__(self, node_name):
        self.node_name = node_name

    def export_certificate(self):
        pass

    def export_eph_pk(self):
        pass

    def import_private_key(self):
        file_name = f"key_pairs/{self.node_name}_private.pem"
        private_key = None
        # RSA key is not pickleable
        with open(file_name, 'r') as f:
           private_key = RSA.import_key(f.read())
        return private_key
    
    def export_priv_key(self):
        pass

    def export_eph_priv_key(self):
        pass
    
    def export_pk(self) -> str:
        file_name = f"key_pairs/{self.node_name}_public.pem"
        public_key = None
        with open(file_name, 'r') as f:
           public_key = f.read()
        return public_key
    
    def import_pk(self, pk: str):
        self.pk = RSA.import_key(pk)

    def import_eph_pk(self,pk):
        pass

    def export_sk(self) -> str:
        self.sk = get_random_bytes(16)
        return b64encode(self.sk).decode('utf-8')

    def import_sk(self, sk: str):
        self.sk = b64decode(sk.encode('utf-8'))

    def import_sk_fs(self, priv_key, eph_priv_key):
        pass

    def sign(self, msg) -> str:
        if not isinstance(msg, bytes):
            msg = msg.encode('utf-8')
        key = self.import_private_key()
        sig = pkcs1_15.new(key).sign(SHA256.new(msg))
        return b64encode(sig).decode('utf-8')

    def verify(self, msg, signature: str):
        if not isinstance(msg, bytes):
            msg = msg.encode('utf-8')
        key = self.pk
        try:
            pkcs1_15.new(key).verify(SHA256.new(msg), b64decode(signature.encode('utf-8')))
            return True
        except Exception as e:
            return False
        
    def encrypt(self, msg) -> str:
        # public key encryption has length limit, and is slow
        # https://pycryptodome.readthedocs.io/en/latest/src/cipher/oaep.html#Crypto.Cipher.PKCS1_OAEP.PKCS1OAEP_Cipher.encrypt
        if not self.pk:
            return None
        if not isinstance(msg, bytes):
            msg = msg.encode('utf-8')
        cipher = PKCS1_OAEP.new(self.pk)
        cipher_text = cipher.encrypt(msg)
        return b64encode(cipher_text).decode('utf-8')
    
    def decrypt(self, msg) -> str:
        msg = b64decode(msg.encode('utf-8'))
        key = self.import_private_key()
        cipher = PKCS1_OAEP.new(key)
        return cipher.decrypt(msg).decode('utf-8')
    
    def encrypt_sk(self, msg) -> (str, str):
        if not self.sk:
            return None
        if not isinstance(msg, bytes):
            msg = msg.encode('utf-8')
        cipher = AES.new(self.sk, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(msg, AES.block_size))
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        return ct, iv

    def decrypt_sk(self, msg: str, iv: str, tag=None) -> str:
        ivb = b64decode(iv.encode('utf-8'))
        ct = b64decode(msg.encode('utf-8'))
        cipher = AES.new(self.sk, AES.MODE_CBC, ivb)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    
    def generate_mac(self, msg):
        pass


# Key Derivation Function
def kdf(x):
    return SHAKE128.new(x).read(32)

class CryptoECC(CryptoImpl):
    def __init__(self, node_name):
        self.node_name = node_name
        eph_priv, eph_pub = utils.generate_ephemeral_key()
        self.eph_priv_key = eph_priv
        self.eph_pub_key = eph_pub

    def export_eph_pk(self):
        return self.eph_pub_key.export_key(format='PEM')

    def import_private_key(self):
        if IS_CERTIFICATE:
            file_name = f"key_pairs/{self.node_name}_new_ecc_private.pem"
        else:
            file_name = f"key_pairs/{self.node_name}_ecc_private.pem"
        private_key = None
        with open(file_name, 'r') as f:
           private_key = ECC.import_key(f.read())
        self.priv_key = private_key
    
    def export_priv_key(self) -> str:
        self.import_private_key()
        return self.priv_key

    def export_eph_priv_key(self):
        return self.eph_priv_key

    def export_certificate(self) -> str:
        cert_path = f"key_pairs/{self.node_name}_ecc.crt"
        cert = utils.load_cert(cert_path)
        cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
        return cert_bytes.decode('utf-8')

    def export_pk(self) -> str:
        if IS_CERTIFICATE:
            cert_path = f"key_pairs/{self.node_name}_ecc.crt"
            cert = utils.load_cert(cert_path)
            pk = utils.get_public_key_from_cert(cert)
            return pk
        file_name = f"key_pairs/{self.node_name}_ecc_public.pem"
        public_key = None
        with open(file_name, 'r') as f:
           public_key = f.read()
        return public_key
    
    def import_pk(self, pk: str):
        self.pk = ECC.import_key(pk)
    
    def import_eph_pk(self, pk: str):
        # receive eph_pk from neighbor
        self.eph_pk = ECC.import_key(pk)

    def export_sk(self) -> str:
        pass

    def import_sk(self, priv_key):
        # TODO: support EDH to guarantee forward secrecy
        self.sk = key_agreement(
            kdf = kdf,
            static_priv = priv_key,
            static_pub = self.pk,
        )
    
    def import_sk_fs(self, priv_key, eph_priv_key):
        # Support forward secrecy, guarantee that the session key is fresh
        self.sk = key_agreement(
            kdf = kdf,
            static_priv = priv_key,
            static_pub = self.pk,
            eph_priv = eph_priv_key,
            eph_pub = self.eph_pk
        )

    def sign(self, msg) -> str:
        # EdDSA, Ed25519
        if not isinstance(msg, bytes):
            msg = msg.encode('utf-8')
        self.import_private_key()
        key = self.priv_key
        signer = eddsa.new(key, 'rfc8032')
        # PureEdDSA
        sig = signer.sign(msg)
        return b64encode(sig).decode('utf-8')

    def verify(self, msg, signature: str):
        if not isinstance(msg, bytes):
            msg = msg.encode('utf-8')
        key = self.pk
        try:
            verifer = eddsa.new(key, 'rfc8032')
            verifer.verify(msg, b64decode(signature.encode('utf-8')))
            return True
        except Exception as e:
            return False
        
    def encrypt(self, msg) -> str:
        # ECC does not support encryption and decryption
        pass
    
    def decrypt(self, msg) -> str:
        pass

    def generate_mac(self, msg) -> str:
        # key confirmation
        if not isinstance(msg, bytes):
            msg = msg.encode('utf-8')
        h = HMAC.new(key=self.sk, digestmod=SHA256)
        h.update(msg)
        return b64encode(h.digest()).decode('utf-8')
    
    def encrypt_sk(self, msg) -> (str, str, str):
        if not self.sk:
            return None
        if not isinstance(msg, bytes):
            msg = msg.encode('utf-8')
        cipher = AES.new(self.sk, AES.MODE_GCM)
        ct, tag = cipher.encrypt_and_digest(msg)
        nonce = b64encode(cipher.nonce).decode('utf-8')
        ct = b64encode(ct).decode('utf-8')
        tag = b64encode(tag).decode('utf-8')
        return ct, nonce, tag

    def decrypt_sk(self, msg: str, nonce: str, tag: str) -> str:
        nonce = b64decode(nonce.encode('utf-8'))
        ct = b64decode(msg.encode('utf-8'))
        tag = b64decode(tag.encode('utf-8'))
        cipher = AES.new(self.sk, AES.MODE_GCM, nonce=nonce)
        pt = cipher.decrypt_and_verify(ct, tag)
        return pt.decode('utf-8')
        
class CryptoStrategy(dict):
    def __init__(self, impl, name):
        self.crypto = impl
        # https://pynative.com/make-python-class-json-serializable/
        self.name = name
        dict.__init__(self, name=name)
    
    def export_certificate(self):
        return self.crypto.export_certificate()
    
    def export_eph_pk(self):
        return self.crypto.export_eph_pk()

    def sign(self, msg):
        return self.crypto.sign(msg)

    def verify(self, msg, signature):
        return self.crypto.verify(msg, signature) 

    def export_priv_key(self):
        return self.crypto.export_priv_key()

    def export_pk(self):
        return self.crypto.export_pk()

    def export_eph_priv_key(self):
        return self.crypto.export_eph_priv_key()

    def import_pk(self, pk):
        return self.crypto.import_pk(pk)

    def import_eph_pk(self,pk):
        return self.crypto.import_eph_pk(pk)

    def export_sk(self):
        return self.crypto.export_sk()

    def import_sk(self, sk):
        return self.crypto.import_sk(sk)

    def import_sk_fs(self, priv_key, eph_priv_key):
        return self.crypto.import_sk_fs(priv_key, eph_priv_key)

    def encrypt(self, msg):
        return self.crypto.encrypt(msg)

    def decrypt(self, msg):
        return self.crypto.decrypt(msg)

    def encrypt_sk(self, msg):
        return self.crypto.encrypt_sk(msg)

    def decrypt_sk(self, msg, iv, tag):
        return self.crypto.decrypt_sk(msg, iv, tag)

    def generate_mac(self, msg):
        return self.crypto.generate_mac(msg)

    def __repr__(self) -> str:
        return self.name
