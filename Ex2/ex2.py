from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from binascii import hexlify, unhexlify
import argparse

def aes_128_ecb_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

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


# def aes_128_cbc_decrypt_block(key, iv, ciphertext, block_index):
#     if len(iv) != AES.block_size:
#         raise ValueError("Initialization vector (IV) must be 16 bytes long.")

#     if len(key) != AES.block_size:
#         raise ValueError("Key must be 16 bytes long.")

#     block_size = AES.block_size
#     start_idx = (block_index - 1) * block_size
#     end_idx = block_index * block_size

#     block = ciphertext[start_idx:end_idx]
#     prev_block = iv if block_index == 1 else ciphertext[start_idx - block_size:end_idx - block_size]

#     decrypted_block = aes_128_ecb_decrypt(block, key)
#     xored_block = bytes([a ^ b for a, b in zip(decrypted_block, prev_block)])

#     return xored_block

def aes_128_cbc_decrypt_block(key, iv, ciphertext, block_index):
    if len(iv) != AES.block_size:
        raise ValueError("Initialization vector (IV) must be 16 bytes long.")

    if len(key) != AES.block_size:
        raise ValueError("Key must be 16 bytes long.")

    block_size = AES.block_size
    start_idx = block_index * block_size
    end_idx = (block_index + 1) * block_size

    block = ciphertext[start_idx:end_idx]
    prev_block = iv if block_index == 0 else ciphertext[start_idx - block_size:end_idx - block_size]

    decrypted_block = aes_128_ecb_decrypt(block, key)
   # xored_block = bytes([a ^ b for a, b in zip(decrypted_block, prev_block)])

    return decrypted_block

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AES-128-CBC Decryption of a Specific Block")
    parser.add_argument("-t", "--ciphertext", required=True, help="Ciphertext in hexadecimal format")
    parser.add_argument("-k", "--key", required=True, help="Key in hexadecimal format")
    parser.add_argument("-iv", "--iv", required=True, help="Initialization Vector (IV) in hexadecimal format")
    parser.add_argument("-b", "--block", type=int, required=True, help="Index of the block to decrypt")
    args = parser.parse_args()

    text = unhexlify(args.ciphertext)
    key = unhexlify(args.key)
    iv = unhexlify(args.iv)
    block_index_to_decrypt = args.block
    
    ciphertext = aes_128_cbc_encrypt(key,iv,text)

    decrypted_block = aes_128_cbc_decrypt_block(key, iv, ciphertext, block_index_to_decrypt)
    print("Decrypted Block:", decrypted_block)