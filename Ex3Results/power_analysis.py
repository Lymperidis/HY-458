"""
This contains classes for simulating a computer running the decryption procsess.

It UNSAFE to use this in production.
Do not use it anywhere except the HY458 Assignments.

Implemented by Nikolaos Boumakis, csdp1358
"""

import random
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.hashes import SHA256

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from binascii import hexlify


def decrypt_message(ciphertext, private_key):
    try:
        decrypted_message = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message.decode()
    except Exception as e:
        print("Decryption failed:", e)
        return None

def reconstruct_private_key(d, public_key):
    
    public_numbers = public_key.public_numbers()
    e = public_numbers.e
    n = public_numbers.n
    
    # Retrieve the prime factors p, q from the public key and private exponent d
    p, q = rsa.rsa_recover_prime_factors(n, e, d)

    # Create the private key object
    private_key = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=rsa.rsa_crt_dmp1(d, p),
        dmq1=rsa.rsa_crt_dmq1(d, q),
        iqmp=rsa.rsa_crt_iqmp(p, q),
        public_numbers=public_numbers
    ).private_key()

    return private_key


class VictimComputer():
    """ The computer that runs the decryption and whose power is being tracked """

    def __init__(self) -> None:
        self.__private_key = generate_private_key(0x10001, 2048)
        self.__public_key = self.__private_key.public_key()

    def _square_multiply_power_trace(self):
        power_trace = [random.uniform(2, 5)
                       for _ in range(random.randint(20, 30))]
        power_trace.extend([random.uniform(0, 1)
                           for _ in range(random.randint(1, 5))])
        power_trace.extend([random.uniform(2, 5)
                           for _ in range(random.randint(20, 30))])

        return power_trace

    def _square_power_trace(self):
        return [random.uniform(2, 5) for _ in range(random.randint(20, 30))]

    def get_public_key(self) -> RSAPublicKey:
        """ Simulate getting the public key from the computer """
        return self.__public_key

    def decrypt(self, ciphertext: bytes) -> list[float]:
        """ Simulate decrypting the ciphertext and tracking the power required """
        _ = self.__private_key.decrypt(
            ciphertext, OAEP(MGF1(SHA256()), SHA256(), None))

        d = self.__private_key.private_numbers().d

        power_trace: list[float] = [random.uniform(0, 1)
                                    for _ in range(random.randint(6, 20))]

        for bit in bin(d)[3:]:
            bit = int(bit)
            # The single bit power trace
            if bit:
                power_trace.extend(self._square_multiply_power_trace())
            else:
                power_trace.extend(self._square_power_trace())

            # The idle time between operations
            power_trace.extend([random.uniform(0, 1)
                                for _ in range(random.randint(10, 20))])

        return power_trace
    
def retrieve_private_exponent(power_trace):
    exponent = '1'  # MSB is always 1
    index = 0

    while index < len(power_trace):
        # Skip the idle period at the start of each cycle
        while index < len(power_trace) and power_trace[index] < 1:
            index += 1

        # If we've reached the end of the power trace, break out of the loop
        if index >= len(power_trace):
            break

        # Start of a power-consuming operation
        operation_start = index

        # Skip over the squaring operation
        while index < len(power_trace) and power_trace[index] >= 2:
            index += 1

        # Measure the length of the operation
        operation_length = index - operation_start

        # Check for a subsequent multiplication operation (bit = 1)
        if index < len(power_trace) and power_trace[index] < 1:
            # Idle period before potential multiplication
            idle_start = index
            while index < len(power_trace) and power_trace[index] < 1:
                index += 1
            idle_length = index - idle_start

            if idle_length <= 5 and (index + 20 <= len(power_trace) and max(power_trace[index:index+20]) >= 2):
                # There is a subsequent multiplication
                exponent += '1'
                # Skip over the multiplication operation
                while index < len(power_trace) and power_trace[index] >= 2:
                    index += 1
            else:
                # Only squaring was performed (bit = 0)
                exponent += '0'

        # Skip the cooldown between operations
        while index < len(power_trace) and power_trace[index] < 1:
            index += 1

    return int(exponent, 2)


def encrypt_message(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def read_words_from_file(file_path):
    with open(file_path, 'r') as file:
        words = [line.strip() for line in file.readlines()]
    return words

def generate_random_message(words, word_count=10):
    return ' '.join(random.choices(words, k=word_count))

def main():
    # Instantiate VictimComputer
    victim = VictimComputer()

    wordlist_file = 'wordlist.txt'

    # Read words from the file
    words = read_words_from_file(wordlist_file)

    # Generate a random message
    random_message = generate_random_message(words, word_count=10)

    print("Random Message:", random_message)
    
    # Assuming victim is an instance of VictimComputer
    public_key = victim.get_public_key()

    # Encrypt the message
    ciphertext = encrypt_message(random_message, public_key)
    print("Encrypted Message:", ciphertext.hex())

    # Decrypt to get power trace
    power_trace = victim.decrypt(ciphertext)

    # Retrieve private exponent from power trace
    d = retrieve_private_exponent(power_trace)

    # Reconstruct the private key
    private_key = reconstruct_private_key(d, public_key)

    # Decrypt and print the message
    decrypted_message = decrypt_message(ciphertext, private_key)
    print("Decrypted Message:", decrypted_message)
    
    
if __name__ == "__main__":
    main()





