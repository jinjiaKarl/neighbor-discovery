# from Crypto.PublicKey import ECC
# from Crypto.Hash import SHAKE128
# from Crypto.Protocol.DH import key_agreement

# # This KDF has been agreed in advance
# def kdf(x):
#     return SHAKE128.new(x).read(32)

# # In a real scenario, this key already exists
# U = ECC.generate(curve='ed25519')
# U_p = U.public_key()

# # In a real scenario, this key is received from the peer
# # and it is verified as authentic
# V = ECC.generate(curve='ed25519')
# V_p = V.public_key()

# s1 = key_agreement(static_priv=U, static_pub=V_p, kdf=kdf)

# s2 = key_agreement(static_priv=V, static_pub=U_p, kdf=kdf)
# print(s1 == s2)
# session_key is an AES-256 key, which will be used to encrypt
# subsequent communications

import os

from flask import Flask

def run():
    app = Flask(__name__)

    @app.route("/")
    def hello_world():
        return "<p>Hello, World!</p>"
    app.run(host='0.0.0.0', port=8888, debug=True)

run()