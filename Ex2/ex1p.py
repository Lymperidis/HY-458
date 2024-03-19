from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify, unhexlify

def aes_128_ecb_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def aes_128_cbc_encrypt(key, iv, plaintext):
    if len(iv) != AES.block_size:
        raise ValueError("Initialization vector (IV) must be 16 bytes long.")

    if len(key) != AES.block_size:
        raise ValueError("Key must be 16 bytes long.")
     
    padding = b'\x00' * (AES.block_size - len(plaintext) % AES.block_size)
    plaintext = plaintext + padding
    
    blocks = [plaintext[i:i + AES.block_size] for i in range(0, len(plaintext), AES.block_size)]

    cipher_text = b""
    prev_block = iv

    for block in blocks:
        xored_block = bytes([a ^ b for a, b in zip(block, prev_block)])
        encrypted_block = aes_128_ecb_encrypt(key, xored_block)
        cipher_text += encrypted_block
        prev_block = encrypted_block

    return cipher_text




def aes_128_ecb_decrypt(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

def remove_after_count(text, count):
    # Ensure count is within the valid range
    count = min(count, len(text))

    # Return the text up to the specified count
    return text[:count]

def aes_128_cbc_decrypt(key, iv, ciphertext):
    if len(iv) != AES.block_size:
        raise ValueError("Initialization vector (IV) must be 16 bytes long.")

    if len(key) != AES.block_size:
        raise ValueError("Key must be 16 bytes long.")

    blocks = [ciphertext[i:i + AES.block_size] for i in range(0, len(ciphertext), AES.block_size)]

    plain_text = b""
    prev_block = iv
    

    for block in blocks:
        decrypted_block = aes_128_ecb_decrypt(key, block)
        xored_block = bytes([a ^ b for a, b in zip(decrypted_block, prev_block)])
        plain_text += xored_block
        prev_block = block
        
    

    return hexlify(plain_text).decode()

def aes_128_cbc_encryption(plaintext, key, iv):
    # Cryptography library
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    
    encryptor = cipher.encryptor()
    ciphertext_cryptography = encryptor.update(plaintext) + encryptor.finalize()
    
    return ciphertext_cryptography
def aes_128_cbc_decryption(ciphertext,key,iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text_cryptography = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_text_cryptography


# Example usage:
parser = argparse.ArgumentParser(description="AES-128-CBC Encryption")
parser.add_argument("-p", "--plaintext", required=True, help="Plaintext in hexadecimal format")
parser.add_argument("-k", "--key", required=True, help="Key in hexadecimal format")
parser.add_argument("-iv", "--iv", required=True, help="Initialization Vector (IV) in hexadecimal format")
args = parser.parse_args()

plaintext = unhexlify(args.plaintext)
key = unhexlify(args.key)
iv = unhexlify(args.iv)

plaintext1 = plaintext

last_non_padding = len(hexlify(plaintext))

cipher_text = aes_128_cbc_encrypt(key, iv, plaintext)
print("Cipher Text:", cipher_text)

plaintext = aes_128_cbc_decrypt(key, iv, cipher_text)
plaintext = remove_after_count(plaintext,last_non_padding)
print("Decrypted Plaintext:",plaintext)

cipher1 = aes_128_cbc_encryption(plaintext1,key,iv)
plain1 = aes_128_cbc_decryption(cipher1,key,iv)

print("Ciphertext (Library) " , cipher1)
print("Plaintext (Library)",hexlify(plain1).decode())

assert plaintext == hexlify(plain1).decode()

print("Encryption and Decryption (Cryptography) are consistent.")

