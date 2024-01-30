from fastapi import FastAPI
import uvicorn
from ca_models import *

import ca
import utils

"""
    Create a CA http server that will be used to sign X.509 certificates to provide the following functionality:
    * provide CA certificate
    * issue a certificate for a given public key
    * provide OCSP endpoint to check the status of certificate (optional)
    * revocate a certificate using CRL (optional)
    * do not support delegation 

    CA uses ed25519 private key and public key
"""

# ca_server = ca.CertificateAuthority()

# python3 -m uvicorn main:app --reload
app = FastAPI()
@app.get("/")
def root():
    return {"Hello": "I am a CA server"}

# @app.post("/csr")
# def csr(csr: Csr):
#     """
#         Create a CSR in the server side, it is not a typical way to do it and it is not safe
#     """
#     csr_data, key_data = ca_server.issue_csr(csr.common_name)
#     return {
#         "csr": csr_data.decode('utf-8'),
#         "key": key_data.decode('utf-8')
#     }

@app.get("/cert")
def cert():
    """
        Return CA certificate
    """
    return {
        "cert": ca_server.cert.decode('utf-8')
    }

@app.post("/issue")
def issue(issue: Issue):
    """
        Issue a certificate for a csr
    """
    cert = ca_server.issue_cert(
        common_name=utils.get_common_name_from_csr(issue.csr),
        pk=utils.get_pk_from_csr(issue.csr),
    )
    return {
        "cert": cert.decode('utf-8')
    }

@app.post("/check")
def check(check: Check):
    """
        Check a certificate
    """
    return {
        "status": ca_server.validate_cert(check.cert)
    }


if __name__ == "__main__":
    ca_server = ca.CertificateAuthority()
    uvicorn.run(app, host="0.0.0.0", port=8001)