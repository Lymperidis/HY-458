import argparse
import binascii

import random
from math import gcd
import math
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives import serialization
from gmpy2 import next_prime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def fermat_vulnerable() -> RSAPublicKey:
    """Creates a RSA public key that is vulnerable to Fermat's factorization algorithm"""
    e = 0x10001

    p = int(next_prime(random.randint(2**511, 2**512-1)))
    q = int(next_prime(p))

    for _ in range(random.randint(30, 50)):
        q = int(next_prime(q))

    assert all((gcd(e, (q-1)*(p-1)),
                (abs(p-q) < pow(p*q, 1/4)))), \
        "There was a problem during key creation. This is not your fault, try running again"

    return RSAPublicNumbers(e, p*q).public_key()


def create_pem_files(private_path: str, public_path: str):
    ''' Creates a key pair and saves them to disk '''
    with open(private_path, 'wb') as priv_f, open(public_path, 'wb') as pub_f:
        priv_key = generate_private_key(0x10001, 2048)

        priv_f.write(priv_key.
                     private_bytes(
                         serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8,
                         serialization.NoEncryption()
                     ))
        pub_f.write(priv_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
))

def isqrt(n):
	x=n
	y=(x+n//x)//2
	while(y<x):
		x=y
		y=(x+n//x)//2
	return x
def fermat(n):
	t0=isqrt(n)+1
	counter=0
	t=t0+counter
	temp=isqrt((t*t)-n)
	while((temp*temp)!=((t*t)-n)):
		counter+=1
		t=t0+counter
		temp=isqrt((t*t)-n)
	s=temp
	p=t+s
	q=t-s
	return int(p),int(q)

def recover_private_key(vulnerable_public_key):
    # Step i: Factor the modulus n of the public key
    n = vulnerable_public_key.public_numbers().n
    p, q = fermat(n)
    
    # Step ii: Using the factors of n calculate φ(n)
    phi_n = (p - 1) * (q - 1)
    
    # Step iii: Use φ(n) and e to calculate d
    e = vulnerable_public_key.public_numbers().e
    d = pow(e, -1, phi_n)
    
    # Step iv: Calculate additional values
    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    
    # Ensure that q has a modular inverse mod p
    iqmp = pow(q, -1, p)
    
    # Step v: Create RSAPrivateNumbers
    private_numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=dmp1,
        dmq1=dmq1,
        iqmp=iqmp,
        public_numbers=vulnerable_public_key.public_numbers()
    )
    
    # Step vi: Create the private key
    private_key = private_numbers.private_key(default_backend())
    
    return private_key



def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='RSA Encryption and Decryption')
    parser.add_argument('-m', '--message', type=str, required=True, help='Plaintext message in hexadecimal format')
    parser.add_argument('-prv', '--private_key_path', type=str, required=True, help='File path to save the private key in PEM format')
    args = parser.parse_args()

    # Convert hexadecimal message to bytes
    plaintext = binascii.unhexlify(args.message)

    # Generate a vulnerable public key
    public_key = fermat_vulnerable()

    # Encrypt the message using the public key
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save the private key to the specified path
    private_key = recover_private_key(public_key)
    with open(args.private_key_path, 'wb') as prv_file:
        prv_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Decrypt the ciphertext using the recovered private key
    decrypted_message = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Print the decrypted message in hexadecimal format
    print("Decrypted Message (Hexadecimal):", binascii.hexlify(decrypted_message).decode('utf-8'))

if __name__ == "__main__":
    main()