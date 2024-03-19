from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import argparse

def calculate_digital_signature(message, private_key):
    # (a) Hash the message using SHA256
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    hash_value = digest.finalize()

    # (b) Convert the hash value from bytes to an integer
    hash_as_int = int.from_bytes(hash_value, byteorder='big')

    # (c) Raise the hash value (as an integer) to the private exponent modulo n
    signature = pow(hash_as_int, private_key.private_numbers().d, private_key.public_key().public_numbers().n)

    # (d) Convert the result back to bytes
    signature_bytes = signature.to_bytes((signature.bit_length() + 7) // 8, byteorder='big')

    return signature_bytes

def print_hex_message(message, label):
    print(f"{label} (Hex): {' '.join(hex(byte)[2:].zfill(2) for byte in message)}")



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

    # (f) Compare the hash of the message with the decrypted signature
    return hash_value == decrypted_signature_bytes

# Example usage:
# Generate RSA key pair

# def modify_message(message):
#     # Modify a single byte in the message
#     modified_message = bytearray(message)
#     modified_message[0] ^= 0x01  # Change the first byte
#     return bytes(modified_message)


def test_signature_generation_and_verification(message, private_key):
    print("Original Message:", message)

    # Calculate the digital signature
    signature = calculate_digital_signature(message, private_key)
    print("Digital Signature:", signature)

    # Verify the digital signature with the original message
    result_original_message = verify_digital_signature(message, signature, private_key.public_key())
    print("Verification with Original Message:", result_original_message)


def main():
    parser = argparse.ArgumentParser(description='Test digital signature generation and verification.')
    parser.add_argument('-m', '--message', required=True, help='The message encoded in hexadecimal format.')
    parser.add_argument('-prv', '--private_key', required=True, help='The private key file path in PEM format.')

    args = parser.parse_args()

    # Convert hex-encoded message to bytes
    message = bytes.fromhex(args.message)

    # Load private key from PEM file
    with open(args.private_key, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # Test digital signature generation and verification
    test_signature_generation_and_verification(message, private_key)

if __name__ == "__main__":
    main()