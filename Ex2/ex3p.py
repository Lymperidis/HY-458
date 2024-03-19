from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import base64
import random
import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import base64
import random
import os
from binascii import hexlify, unhexlify


def read_words_from_file(file_path):
    with open(file_path, 'r') as file:
        words = file.read().split()
    return words

def create_random_text(words, block_size):
    random.shuffle(words)
    random_text = ' '.join(words[:block_size])
    return random_text


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
    
    print("Number of blocks : ",len(blocks))
    for i,block in enumerate(blocks):
        decrypted_block = aes_128_ecb_decrypt(key, block)
        if i == 1:
            #xored_block = bytes(16)
            block = bytes(16)
            
        else:
            xored_block = bytes([a ^ b for a, b in zip(decrypted_block, prev_block)])
            
        plain_text += xored_block
        prev_block = block

        
    

    return plain_text #plain_text.decode('utf-8').rstrip('\x00')

if __name__ == "__main__":
    file_path = "wordlist.txt"  
    words = read_words_from_file(file_path)
    
    # Create a random message that is 48 bytes long
    random_message = create_random_text(words, 48)
    print(random_message)
    
    # Convert the text to bytes
    random_message_bytes = random_message.encode('utf-8')
    
    key = os.urandom(16)
    iv=key
    
   # length = len()
    ciphertext = aes_128_cbc_encrypt(key, iv, random_message_bytes)
    plaintext = aes_128_cbc_decrypt(key, iv, ciphertext)
    
    print("Ciphertext: ",ciphertext)
    #remove_after_count(plaintext,)
    print("Decode : ",plaintext)
    
    