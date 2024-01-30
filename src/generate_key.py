from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
import sys

def generate_rsa():
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open("key_pairs/vm1_private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("key_pairs/vm1_public.pem", "wb")
    file_out.write(public_key)
    file_out.close()

    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open("key_pairs/vm2_private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("key_pairs/vm2_public.pem", "wb")
    file_out.write(public_key)
    file_out.close()

def generate_ecc():
    key = ECC.generate(curve='ed25519')
    private_key = key.export_key(format='PEM')
    file_out = open("key_pairs/vm1_ecc_private.pem", "wt")
    file_out.write(private_key)
    file_out.close()

    public_key = key.public_key().export_key(format='PEM')
    file_out = open("key_pairs/vm1_ecc_public.pem", "wt")
    file_out.write(public_key)
    file_out.close()

    key = ECC.generate(curve='ed25519')
    private_key = key.export_key(format='PEM')
    file_out = open("key_pairs/vm2_ecc_private.pem", "wt")
    file_out.write(private_key)
    file_out.close()

    public_key = key.public_key().export_key(format='PEM')
    file_out = open("key_pairs/vm2_ecc_public.pem", "wt")
    file_out.write(public_key)
    file_out.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 generate_key.py <rsa|ecc>")
        exit(1)
    if sys.argv[1] == "rsa":
        generate_rsa()
    elif sys.argv[1] == "ecc":
        generate_ecc()
    else:
        exit(1)