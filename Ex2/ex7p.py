from Crypto.Cipher import AES
import argparse

# def gcm_like_encrypt_block(plaintext_block, key, iv):
#     cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
#     ciphertext_block, tag   = cipher.encrypt_and_digest(plaintext_block)
#     return ciphertext_block , tag ,iv 

def gcm_like_encrypt_block(plaintext_block, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_block)
    iv = cipher.nonce
    return (ciphertext, iv, tag)


def gcm_like_decrypt_single_block(ciphertext, key, iv, block_index):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    block_size = 16  # Assuming a block size of 16 bytes

    start_idx = (block_index - 1) * block_size
    end_idx = block_index * block_size
    current_block = ciphertext[start_idx:end_idx]       #extract the block that the index shows 
    
    plaintext = cipher.decrypt(current_block)
    return plaintext

def main():
    parser = argparse.ArgumentParser(description='GCM-Like Encryptor/Decryptor with Simulated Random Access')
    parser.add_argument('-e', action='store_true', help='Encrypt mode')
    parser.add_argument('-d', action='store_true', help='Decrypt mode')
    parser.add_argument('-t', required=True, help='Text (plaintext or ciphertext) in hexadecimal format')
    parser.add_argument('-c', required=False, help='Ciphertext in hexadecimal format')
    parser.add_argument('-k', required=True, help='Key in hexadecimal format')
    parser.add_argument('-iv', required=False, help='Initialization Vector (IV) in hexadecimal format')
    parser.add_argument('-i', type=int, help='Block index to decrypt')
    parser.add_argument('-tag',required=False, help="Tag")


    args = parser.parse_args()

    text = bytes.fromhex(args.t)
    key = bytes.fromhex(args.k)

    if args.e:
        plaintext = text
        ciphertext_block , nonce , tag = gcm_like_encrypt_block(plaintext, key)
        print(f'Ciphertext Block: {ciphertext_block.hex()}')
        print(f'Tag: {tag.hex()}')
        print(f'Nonce: {nonce.hex()}')
        

    elif args.d:
        iv = bytes.fromhex(args.iv)
        tag = bytes.fromhex(args.tag)
        if args.i is None:
            print("Please provide a block index to decrypt.")
            return

        ciphertext = text
        block_index = args.i
        ciphertext = text
        decrypted_block = gcm_like_decrypt_single_block(ciphertext, key, iv, block_index)
        print(f'Decrypted Block {block_index}: {decrypted_block.hex()}')

if __name__ == '__main__':
    main()