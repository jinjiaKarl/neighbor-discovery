from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
import os

import utils
import constant

# reference: https://github.com/OwnCA/ownca/blob/master/ownca/ownca.py
class CertificateAuthority():

    def __init__(
            self,
            ca_storage: str = "key_pairs",
            ca_common_name: str = "Securitas CA",
            max_days: int = 365
    ) -> None:
        self._ca_strorage = ca_storage
        self._ca_common_name = ca_common_name
        # check if CA keypair and certificate exist
        status = utils.check_ca_status(ca_storage)
        if status.key:
            # exist, load them
            self._key = utils.load_key(os.path.join(ca_storage, constant.CA_KEY))
            self._pk = utils.load_pk(os.path.join(ca_storage, constant.CA_PUBLIC_KEY))
            self._cert = utils.load_cert(os.path.join(ca_storage, constant.CA_CERT))
            return
        # create a keypair and self-sign certificate
        private_key = Ed25519PrivateKey.generate()
        self._key = private_key
        utils.store_file(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ), os.path.join(ca_storage, constant.CA_KEY))
        public_key = private_key.public_key()
        self._pk = public_key
        utils.store_file(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ), os.path.join(ca_storage, constant.CA_PUBLIC_KEY))
        cert = utils.issue_cert(
            ca_common_name=ca_common_name,
            common_name=ca_common_name,
            max_days=max_days,
            key=private_key,
            pk=public_key,
            ca=True
        )
        self._cert = cert
        utils.store_file(
            cert.public_bytes(serialization.Encoding.PEM),
            os.path.join(ca_storage, constant.CA_CERT)
        )

    @property
    def key(self) -> Ed25519PrivateKey:
        return self._key

    @property
    def pk(self) -> Ed25519PublicKey:
        return self._pk

    @property
    def cert(self) -> bytes:
        return self._cert.public_bytes(serialization.Encoding.PEM)

    @property
    def ca_storage(self) -> str:
        return self._ca_strorage

    @property
    def ca_common_name(self) -> str:
        return self._ca_common_name

    def issue_cert(
            self,
            common_name: str,
            pk: Ed25519PublicKey,
            max_days: int = 365,
    ) -> bytes:
        cert = utils.issue_cert(
            ca_common_name=self._ca_common_name,
            common_name=common_name,
            max_days=max_days,
            key=self._key,
            pk=pk,
            ca=False
        )
        path = os.path.join(self._ca_strorage, f"{common_name}_issued_ecc.crt")
        data = cert.public_bytes(serialization.Encoding.PEM)
        utils.store_file(data, path)
        return data

    # deprecated
    def issue_csr(
            self,
            common_name: str,
    ) -> tuple[bytes, bytes]:
        request, private_key = utils.issue_csr(
            common_name=common_name,
        )
        csr_path = os.path.join(self._ca_strorage, f"{common_name}_ecc_csr.pem")
        csr_data = request.public_bytes(serialization.Encoding.PEM)
        utils.store_file(csr_data, csr_path)
        key_path = os.path.join(self._ca_strorage, f"{common_name}_issued_ecc_private.pem")
        key_data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        utils.store_file(key_data, key_path)
        return csr_data, key_data

    def validate_cert(self, cert: bytes) -> bool:
        cert_obj = x509.load_pem_x509_certificate(cert.encode('utf-8'))
        print(f"checking certificate: CA subject: {self._cert.subject}, issuer: {cert_obj.issuer}, CN: {cert_obj.subject}")
        try:
            cert_obj.verify_directly_issued_by(self._cert)
            return True
        except Exception as e:
            print(e)
            return False

