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
    
    
def encrypt_text_aes_gcm(text, key,nonce):
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, text, None)
    return (ciphertext)

def decrypt_text_aes_gcm(ciphertext, key, nonce, tag):
    aesgcm = AESGCM(key)
    decrypted_data = aesgcm.decrypt(nonce, ciphertext, tag)
    return (decrypted_data.decode('utf-8'))



def main():
    parser = argparse.ArgumentParser(description='AES-128-GCM Encryptor/Decryptor')
    parser.add_argument('-e', action='store_true', help='Encrypt mode')
    parser.add_argument('-d', action='store_true', help='Decrypt mode')
    parser.add_argument('-t', required=True, help='Text (plaintext or ciphertext) in hexadecimal format')
    parser.add_argument('-k', required=True, help='Key in hexadecimal format')
    parser.add_argument('-iv', help='Initialization Vector (hexadecimal) for decryption mode')
    parser.add_argument('-g', help='Tag for decryption mode')

    args = parser.parse_args()

    text = bytes.fromhex(args.t)
    key = bytes.fromhex(args.k)

    if args.e:
        ciphertext, iv, tag = encrypt(text, key)
        print(f'Ciphertext: {ciphertext.hex()}')
        print(f'IV: {iv.hex()}')
        print(f'Tag: {tag.hex()}')
        
        
        
        aes_cipher = encrypt_text_aes_gcm(text,key,iv)
        
        print(f'Library Ciphertext:{aes_cipher.hex()}')
        
        
    elif args.d:
        if not args.iv or not args.g:
            print('Error: IV and Tag are required for decryption mode')
            return

        iv = bytes.fromhex(args.iv)
        tag = bytes.fromhex(args.g)
        try:
            print("This is the tag: ",tag)
            plaintext = decrypt(text, key, iv, tag)
            print(f'Plaintext: {hexlify(plaintext).decode()}')
            
            #aes_plaintext = decrypt_text_aes_gcm(text, key, iv, tag)
            
            #print(f'Library Plaintext:{hexlify(aes_plaintext).decode()}')
            
            
        except InvalidTag as e:
            print(f'Error: {e}')
    

if __name__ == '__main__':
    main()
