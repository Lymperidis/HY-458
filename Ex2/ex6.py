import argparse
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
import secrets
from binascii import hexlify, unhexlify

class InvalidTag(Exception):
    pass

def generate_aes_key():
    return secrets.token_bytes(16)

def encrypt(plaintext, key, ad):
    cipher = AES.new(key, AES.MODE_GCM)
    #iv = get_random_bytes(16)
    #cipher.update(iv)
    cipher.update(ad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    iv = cipher.nonce
    return (ciphertext, iv, tag)

def decrypt(ciphertext, key, iv, tag,ad):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    cipher.update(ad)
    #cipher.update(iv)
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
    elif element == 'ad':
        return value + b'0', b'0' * 16, b'0' * 16
    else:
        raise ValueError(f"Invalid encryption element: {element}")

def main():
    parser = argparse.ArgumentParser(description='AES-128-GCM Encryptor/Decryptor with AD')
    parser.add_argument('-e', action='store_true', help='Encrypt mode')
    parser.add_argument('-d', action='store_true', help='Decrypt mode')
    parser.add_argument('-c', action='store_true', help='Corruption mode')
    parser.add_argument('-t', required=True, help='Text (plaintext or ciphertext) in hexadecimal format')
    parser.add_argument('-a', required=False, help='Associated Data (AD) in hexadecimal format')
    parser.add_argument('-k', required=True, help='Key in hexadecimal format')
    parser.add_argument('-iv', help='Initialization Vector (hexadecimal) for decryption or corruption mode')
    parser.add_argument('-tag',required=False, help="Tag")

    args = parser.parse_args()

    text = bytes.fromhex(args.t)
    key = bytes.fromhex(args.k)
    ad = bytes.fromhex(args.a) if args.a else b''
    iv = bytes.fromhex(args.iv) if args.iv else None
    tag = bytes.fromhex(args.tag) if args.tag else None
    if args.e:
        ciphertext, iv, tag = encrypt(text, key, ad)
        print(f'Ciphertext: {ciphertext.hex()}')
        print(f'IV: {iv.hex()}')
        print(f'Tag: {tag.hex()}')
    elif args.d:
        try:
            plaintext = decrypt(text, key, iv, tag,ad)
            print(f'Plaintext: {hexlify(plaintext).decode()}')
        except InvalidTag as e:
            print(f'Decryption failed: {e}')
    elif args.c:
        # Simulate corruption and attempt decryption
        for element in ['c', 'iv', 'key', 'tag', 'ad']:
            damaged_text, damaged_iv, damaged_tag = damage_element(element, text)
            try:
                if element == 'ad':
                    decrypt(damaged_text, key, iv, tag, damaged_tag)
                else:
                    decrypt(damaged_text, key, damaged_iv, damaged_tag, ad)
                print(f'Damaged {element.capitalize()} Decryption Succeeded')
            except InvalidTag as e:
                print(f'Damaged {element.capitalize()} Decryption Failed: {e}')

if __name__ == '__main__':
    main()