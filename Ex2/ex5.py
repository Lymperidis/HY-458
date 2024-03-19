import argparse
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import secrets
from binascii import hexlify, unhexlify

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode

class InvalidTag(Exception):
    pass

def encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    iv = cipher.nonce
    return (ciphertext, iv, tag)

def decrypt(ciphertext, key, iv, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except ValueError as e:
        raise InvalidTag("Decryption failed: Invalid tag") from e

def damage_element(element, value):
    if element == 'c':
        return b'0' * len(value), value[16:], value[:16]
    elif element == 'iv':
        return value[:8] + b'0' * 8, value[8:], b'0' * 16
    elif element == 'key':
        return b'0' * len(value), value, b'0' * 16
    elif element == 'tag':
        return value[:8] + b'0' * 8, value[8:], b'0' * 16
    else:
        raise ValueError(f"Invalid encryption element: {element}")

def main():
    parser = argparse.ArgumentParser(description='AES-128-GCM Encryptor/Decryptor')
    parser.add_argument('-p', required=True, help='Plaintext')
    parser.add_argument('-k', required=True, help='Key in hexadecimal format')
    parser.add_argument('-e', nargs='+', choices=['c', 'iv', 'key', 'tag'], help='Encryption elements to damage')
    args = parser.parse_args()

    plaintext = bytes.fromhex(args.p)
    key = bytes.fromhex(args.k)

    ciphertext, iv, tag = encrypt(plaintext, key)
    print(f'Ciphertext: {ciphertext.hex()}')
    

    if args.e:
        for element in args.e:
            damaged_ciphertext, damaged_iv, damaged_tag = damage_element(element, ciphertext)
            try:
                decrypted_text = decrypt(damaged_ciphertext, key, damaged_iv, damaged_tag)
                print(f'Damaged {element.capitalize()} Decryption Succeeded: {decrypted_text.decode("utf-8")}')
            except InvalidTag as e:
                print(f'Damaged {element.capitalize()} Decryption Failed: {e}')

if __name__ == '__main__':
    main()