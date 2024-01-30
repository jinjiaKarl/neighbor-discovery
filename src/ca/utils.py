from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
import json
import base64
import typing
import datetime
import os

import constant

one_day = datetime.timedelta(1, 0, 0)

def issue_cert(max_days: int = 365, 
               ca_common_name: str = "Securitas CA", 
               common_name: str = "Securitas CA", 
               oids: list[x509.NameAttribute] = None,
               key: Ed25519PrivateKey = None,
               pk: Ed25519PublicKey = None, 
               ca: bool = True,
               ) -> x509.Certificate:
    """
        Issue a certificate for a given public key
    """
    if oids is None:
        oids = []
    oids.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name(oids))
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ca_common_name)]))
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(
        datetime.datetime.today() + (one_day * max_days)
    )
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(pk)

    builder = builder.add_extension(
        x509.BasicConstraints(ca=ca, path_length=None), critical=True
    )

    certificate = builder.sign(
        private_key=key, algorithm=None
    )
    return certificate

def issue_csr(common_name: str) -> tuple[x509.CertificateSigningRequest,Ed25519PrivateKey]:
    private_key = Ed25519PrivateKey.generate()
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )
    request = builder.sign(
        private_key=private_key, algorithm=None
    )
    return request, private_key

def load_cert(path: str) -> x509.Certificate:
    with open(path, "r") as f:
        cert = x509.load_pem_x509_certificate(f.read().encode("utf-8"))
    return cert

def load_key(path: str) -> Ed25519PrivateKey:
    with open(path, "r") as f:
        key = serialization.load_pem_private_key(
            data=f.read().encode("utf-8"),
            password=None
        )
    return key

def load_pk(path: str) -> Ed25519PublicKey:
    with open(path, "r") as f:
        key = serialization.load_pem_public_key(
            data=f.read().encode("utf-8")
        )
    return key

def load_csr(path: typing.Union[str, None] = None, data: bytes = None) -> x509.CertificateSigningRequest:
    if path is not None:
        with open(path, "r") as f:
            csr = x509.load_pem_x509_csr(f.read().encode("utf-8"))
    elif data is not None:
        csr = x509.load_pem_x509_csr(data)
    else:
        raise ValueError("Either path or data must be not None")
    return csr

def convert_to_send_data(data: bytes) -> bytes:
    base64_bytes = base64.b64encode(data)
    base64_str = base64_bytes.decode("utf-8")
    json_data = json.dumps(base64_str)
    byte_data = json_data.encode("utf-8")
    return byte_data

def convert_to_receive_data(data: bytes) -> bytes:
    json_data = data.decode("utf-8")
    obj = json.loads(json_data)
    base64_bytes = obj.encode("utf-8")
    orig_data = base64.b64decode(base64_bytes)
    return orig_data

def get_common_name_from_csr(csr: str) -> str:
    csr = x509.load_pem_x509_csr(csr.encode('utf-8'))
    return csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

def get_pk_from_csr(csr: str) -> Ed25519PublicKey:
    csr = x509.load_pem_x509_csr(csr.encode('utf-8'))
    return csr.public_key()

@dataclass
class CAStatus:
    certificate: bool = False
    key: bool = False
    public_key: bool = False


def check_ca_status(ca_storage: str) -> CAStatus:
    if not os.path.exists(ca_storage):
        os.mkdir(ca_storage)
    
    status = CAStatus()

    if os.path.exists(os.path.join(ca_storage, constant.CA_CERT)):
        status.certificate = True
    
    if os.path.exists(os.path.join(ca_storage, constant.CA_KEY)):
        status.key = True
    
    if os.path.exists(os.path.join(ca_storage, constant.CA_PUBLIC_KEY)):
        status.public_key = True

    return status    

def store_file(data: bytes, path: str, force: bool = False) -> bool:
    # if os.path.exists(path) and force is False:
    #     raise FileExistsError(f"{path} already exists.")

    try:
        with open(path, "w") as f:
            f.write(data.decode("utf-8"))

    except OSError as err:
        raise err

    return True
