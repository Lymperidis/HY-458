import argparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import argparse

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
        

def calculate_digital_signature(private_key, message):
    # (a) Hash the message using SHA256
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    
    # Ensure that the message is bytes
    if not isinstance(message, bytes):
        raise TypeError("Message must be a bytes-like object.")
        
        
    digest.update(message)
    hash_value = digest.finalize()

    # (b) Convert the hash value from bytes to an integer
    hash_as_int = int.from_bytes(hash_value, byteorder='big')

    # (c) Raise the hash value (as an integer) to the private exponent modulo n
    signature = pow(hash_as_int, private_key.private_numbers().d, private_key.public_key().public_numbers().n)

    # (d) Convert the result back to bytes
    signature_bytes = signature.to_bytes((signature.bit_length() + 7) // 8, byteorder='big')

    return signature_bytes


def modify_message_and_sign(original_message,  public_key):
    # Modify the message by changing the first byte to "G"
    
    if not isinstance(original_message, bytes):
        raise TypeError("Original message must be a bytes-like object.")
    
    modified_message = b'G' + original_message[1:]

    # Retrieve the private key from the public key
    private_key = recover_private_key(public_key)

    
    # Create the signature for the modified message
    signature = calculate_digital_signature(private_key, modified_message)

    return modified_message, signature

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

def verify_digital_signature(message, signature, public_key):
    # (b) Convert the signature from bytes to an integer
    signature_as_int = int.from_bytes(signature, byteorder='big')

    # (c) Verify the signature using RSA without padding
    decrypted_signature = pow(signature_as_int, public_key.public_numbers().e, public_key.public_numbers().n)

    # (d) Convert the result back to bytes
    decrypted_signature_bytes = decrypted_signature.to_bytes((decrypted_signature.bit_length() + 7) // 8, byteorder='big')

    # (e) Hash the original message using SHA256
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    hash_value = digest.finalize()


    return hash_value == decrypted_signature_bytes

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Modify a message and create a signature.")
    parser.add_argument("-m", "--message", required=True, help="Original message in hexadecimal format.")
    args = parser.parse_args()

    # Assume you have a function to generate a vulnerable public key
    public_key = fermat_vulnerable()
    
    message_bytes = bytes.fromhex(args.message)

    # Modify the message and create the signature
    modified_message, signature = modify_message_and_sign(message_bytes, public_key)

    
    # Print the modified message and its signature
    print("Modified Message:", modified_message)
    print("Signature:", signature)

    # Save the private key to the specified path
    verify = verify_digital_signature(modified_message,signature,public_key)
    print("Verified: ",verify)

if __name__ == "__main__":
    main()