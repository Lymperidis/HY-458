import time
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import matplotlib.pyplot as plt

def generate_random_data(size):
    return os.urandom(size)

def test_encryption_speed(algorithm, key, data):
    iv = os.urandom(16)  # Generate a random IV (Initialization Vector)
    cipher = Cipher(algorithm(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    start_time = time.time()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    elapsed_time = time.time() - start_time
    return elapsed_time, encrypted_data, iv

def test_encryption_speedcha(algorithm, key, data):
    nonce = os.urandom(16)  # Generate a random nonce
    cipher = Cipher(algorithm(key, nonce=nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    start_time = time.time()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    elapsed_time = time.time() - start_time
    return elapsed_time, encrypted_data, nonce

def test_decryption_speed(algorithm, key, iv, encrypted_data):
    cipher = Cipher(algorithm(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    start_time = time.time()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    elapsed_time = time.time() - start_time
    return elapsed_time, decrypted_data

def test_decryption_speedcha(algorithm, key, nonce, encrypted_data):
    cipher = Cipher(algorithm(key, nonce=nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    start_time = time.time()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    elapsed_time = time.time() - start_time
    return elapsed_time, decrypted_data

def main():
    # data_size = (100 * 1024 * 1024 )* 2 # 100 MB
    # key = os.urandom(32)  # 256-bit key

    # # AES with CBC mode
    # aes_algorithm = algorithms.AES
    # data = generate_random_data(data_size)

    # # Encryption
    # aes_encryption_time, encrypted_data_aes,iv = test_encryption_speed(aes_algorithm, key, data)

    # # Decryption
    # aes_decryption_time, decrypted_data_aes = test_decryption_speed(aes_algorithm, key,iv, encrypted_data_aes)

    # # ChaCha20
    # chacha_algorithm = algorithms.ChaCha20
    # data = generate_random_data(data_size)

    # # Encryption
    # chacha_encryption_time, encrypted_data_chacha,iv= test_encryption_speedcha(chacha_algorithm, key, data)

    # # Decryption
    # chacha_decryption_time, decrypted_data_chacha = test_decryption_speedcha(chacha_algorithm, key,iv, encrypted_data_chacha)

    data_size = (100 * 1024 * 1024) * 2  # 200 MB
    key = os.urandom(32)  # 256-bit key

    # Lists to store results
    encryption_times_aes = []
    decryption_times_aes = []
    encryption_times_chacha = []
    decryption_times_chacha = []

    for _ in range(5):  # Run the tests 5 times for better average results
        # AES with CBC mode
        aes_algorithm = algorithms.AES
        data = generate_random_data(data_size)

        # Encryption
        aes_encryption_time, encrypted_data_aes, iv_aes = test_encryption_speed(aes_algorithm, key, data)
        encryption_times_aes.append(aes_encryption_time)

        # Decryption
        aes_decryption_time, _ = test_decryption_speed(aes_algorithm, key, iv_aes, encrypted_data_aes)
        decryption_times_aes.append(aes_decryption_time)

        # ChaCha20
        chacha_algorithm = algorithms.ChaCha20
        data = generate_random_data(data_size)

        # Encryption
        chacha_encryption_time, encrypted_data_chacha, nonce_chacha = test_encryption_speedcha(chacha_algorithm, key, data)
        encryption_times_chacha.append(chacha_encryption_time)

        # Decryption
        chacha_decryption_time, _ = test_decryption_speedcha(chacha_algorithm, key, nonce_chacha, encrypted_data_chacha)
        decryption_times_chacha.append(chacha_decryption_time)

    # Plotting
    plt.figure(figsize=(10, 6))

    # AES
    plt.plot(encryption_times_aes, label='AES Encryption', marker='o')
    plt.plot(decryption_times_aes, label='AES Decryption', marker='o')

    # ChaCha20
    plt.plot(encryption_times_chacha, label='ChaCha20 Encryption', marker='o')
    plt.plot(decryption_times_chacha, label='ChaCha20 Decryption', marker='o')

    plt.xlabel('Test Iteration')
    plt.ylabel('Time (seconds)')
    plt.title('Encryption and Decryption Speed Comparison')
    plt.legend()

    # Save the plot to a file
    plt.savefig('encryption_decryption_plot(chacha,aes).png')
    plt.show()
    
    
if __name__ == "__main__":
    main()