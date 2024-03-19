import matplotlib.pyplot as plt
from collections import Counter
import csv
import random
import numpy as np
import os

def getLetterCount(file_path):
    try:
        with open(file_path, 'r',encoding="UTF-8") as file:
            text = file.read()
            
    except Exception:
        print(f"File not found:{file_path}")
        return None
    
    # Remove spaces and convert text to lowercase
    text = text.replace(" ", "").lower()

    # Define the Latin alphabet
    alphabet = 'abcdefghijklmnopqrstuvwxyz1234567890'

    # Count the frequency of each letter in the text
    letter_counts = Counter(text)

    # Initialize counts for all letters in the alphabet
    alphabet_counts = {letter: 0 for letter in alphabet}

    # Update counts with actual letter frequencies
    for letter, count in letter_counts.items():
        if letter in alphabet:
            alphabet_counts[letter] = count

    return alphabet_counts


def countCharactersInFile(file_path):
    try:
        with open(file_path, 'r') as file:
            text = file.read()
            return len(text)
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None
   
   
def saveLetterFrequencyToCSV(file, file_path,character_count):
    letter_frequency = getLetterCount(file)
    delimiter = '.'
    with open(file_path, 'w', newline='') as csvfile:
        fieldnames = ['Letter', 'Frequency']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        for letter, frequency in letter_frequency.items():
            writer.writerow({'Letter': letter, 'Frequency': frequency})
        write1 = csv.writer(csvfile,delimiter= delimiter)
        write1.writerow(f"All the characters are : {character_count}" ) 
 
def plotLetterFrequency(letter_counts):
    alphabet = list(letter_counts.keys())
    frequency = list(letter_counts.values())

    plt.bar(alphabet, frequency)
    plt.xlabel('Letters')
    plt.ylabel('Frequency')
    plt.title('Letter Frequency in Text')
    plt.show()

def polybius_encode(file_path):
    try:
        with open(file_path, 'r') as file:
            message = file.read()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None

    polybius_square = {
        'a': '11', 'b': '12', 'c': '13', 'd': '14', 'e': '15',
        'f': '21', 'g': '22', 'h': '23', 'i': '24', 'j': '24',
        'k': '25', 'l': '31', 'm': '32', 'n': '33', 'o': '34',
        'p': '35', 'q': '41', 'r': '42', 's': '43', 't': '44',
        'u': '45', 'v': '51', 'w': '52', 'x': '53', 'y': '54',
        'z': '55', ' ': ' '
    }

    encoded_message = ""
    for char in message.lower():
        if char in polybius_square:
            encoded_message += polybius_square[char]
    try:
        with open("Polybius_Square_Encoding.txt", 'w') as output_file:
            output_file.write(encoded_message)
    except IOError:
        print(f"Unable to write to the output file: Polybius_Square_Encoding.txt")        

    return encoded_message


def caesar_cipher_encode(input_file_path,  shift=13):
    try:
        with open(input_file_path, 'r') as input_file:
            text = input_file.read()
    except FileNotFoundError:
        print(f"Input file not found: {input_file_path}")
        return

    encoded_text = ""
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            char = char.lower()
            char_code = ord(char)
            shifted_char_code = (char_code - ord('a') + shift) % 26 + ord('a')
            if is_upper:
                char = chr(shifted_char_code).upper()
            else:
                char = chr(shifted_char_code)
        encoded_text += char

    try:
        with open("Caeser_encoding.txt3", 'w') as output_file:
            output_file.write(encoded_text)
    except IOError:
        print(f"Unable to write to the output file: Caeser_encoding.txt")
        
        
        
def monoalphabetic_cipher(input_file_path,cipher_key=None):
    if cipher_key is None:
        # Default Atbash cipher key (reversed alphabet)
        cipher_key = str.maketrans(
            "abcdefghijklmnopqrstuvwxyz",
            "zyxwvutsrqponmlkjihgfedcba"
        )

    try:
        with open(input_file_path, 'r') as input_file:
            text = input_file.read()
    except FileNotFoundError:
        print(f"Input file not found: {input_file_path}")
        return

    encoded_text = text.translate(cipher_key)

    try:
        with open("Monoalphabetic_Atbash3.txt", 'w') as output_file:
            output_file.write(encoded_text)
    except IOError:
        print(f"Unable to write to the output file: Monoalphabetic_Atbash.txt")
        
    
def book_cipher_encode(input_file_path, book_key_file_path):
    # Read the input text
    try:
        with open(input_file_path, 'r') as input_file:
            input_text = input_file.read()
    except FileNotFoundError:
        print(f"Input file not found: {input_file_path}")
        return

    # Read the book key from a file
    try:
        with open(book_key_file_path, 'r') as key_file:
            book_key = {}
            for line in key_file:
                word, code = line.strip().split()
                book_key[word] = code
    except FileNotFoundError:
        print(f"Book key file not found: {book_key_file_path}")
        return

    encoded_text = []

    # Replace each word in the input text with its corresponding code from the book key
    for word in input_text.split():
        if word in book_key:
            encoded_text.append(book_key[word])
        else:
            encoded_text.append(word)  # Keep the word unchanged if not in the book key

    # Join the encoded words to form the encoded text
    encoded_text = ' '.join(encoded_text)

    # Write the encoded text to an output file
    try:
        with open("Book_Encoding.txt", 'w') as output_file:
            output_file.write(encoded_text)
    except IOError:
        print(f"Unable to write to the output file: Book_Encoding.txt")

def playfair_cipher_encode(message, keyword):
    # Define the Playfair cipher square
    alphabet = 'abcdefghiklmnopqrstuvwxyz'  # 'j' is removed, and 'i' and 'j' are treated as the same letter
    table = [['' for _ in range(5)] for _ in range(5)]

    keyword = keyword.lower().replace('j', 'i')  # Remove 'j' and treat 'i' and 'j' as the same letter
    keyword_set = set()
    
    # Build the Playfair square using the keyword
    row, col = 0, 0
    for char in keyword:
        if char not in keyword_set:
            table[row][col] = char
            keyword_set.add(char)
            col += 1
            if col == 5:
                col = 0
                row += 1
    
    for char in alphabet:
        if char not in keyword_set:
            table[row][col] = char
            col += 1
            if col == 5:
                col = 0
                row += 1
    
    # Helper function to get the coordinates of a letter in the Playfair square
    def get_coordinates(letter):
        for i in range(5):
            for j in range(5):
                if table[i][j] == letter:
                    return (i, j)
    
    # Preprocess the message by removing spaces and making it lowercase
    message = message.replace(' ', '').lower().replace('j', 'i')
    
    # Ensure message length is even
    if len(message) % 2 != 0:
        message += 'x'
    
    encoded_message = ''
    
    # Iterate over the message in pairs
    i = 0
    while i < len(message):
        pair = message[i:i+2]
        if pair[0] == pair[1]:
            pair = pair[0] + 'x'
            i += 1
        
        char1, char2 = pair[0], pair[1]
        row1, col1 = get_coordinates(char1)
        row2, col2 = get_coordinates(char2)
        
        if row1 == row2:
            encoded_char1 = table[row1][(col1 + 1) % 5]
            encoded_char2 = table[row2][(col2 + 1) % 5]
        elif col1 == col2:
            encoded_char1 = table[(row1 + 1) % 5][col1]
            encoded_char2 = table[(row2 + 1) % 5][col2]
        else:
            encoded_char1 = table[row1][col2]
            encoded_char2 = table[row2][col1]
        
        encoded_message += encoded_char1 + encoded_char2
        i += 2
    
    return encoded_message

def playfair_cipher_encode_from_file(input_file_path, keyword):
    # Read the input text from the input file
    try:
        with open(input_file_path, 'r') as input_file:
            message = input_file.read()
    except FileNotFoundError:
        print(f"Input file not found: {input_file_path}")
        return

    # Encode the message using the Playfair cipher
    encoded_message = playfair_cipher_encode(message, keyword)

    # Write the encoded message to the output file
    with open("Playfair.txt", 'w') as output_file:
        output_file.write(encoded_message)

def vigenere_cipher_encrypt_from_file(input_file_path, keyword):
    try:
        with open(input_file_path, 'r') as input_file:
            message = input_file.read().lower()
    except FileNotFoundError:
        print(f"Input file not found: {input_file_path}")
        return

    encrypted_message = ""
    keyword = keyword.lower()
    keyword_length = len(keyword)
    keyword_index = 0

    for char in message:
        if char.isalpha():
            key_char = keyword[keyword_index % keyword_length]
            shift = ord(key_char) - ord('a')
            encrypted_char = chr(((ord(char) - ord('a') + shift) % 26) + ord('a'))
            encrypted_message += encrypted_char
            keyword_index += 1
        else:
            encrypted_message += char

    try:
        with open("Vigenere_Ciphyer.txt", 'w') as output_file:
            output_file.write(encrypted_message)
    except IOError:
        print(f"Unable to write to the output file: Vigenere_Ciphyer.txt")

def running_key_encrypt(input_file, key, output_file):
    with open(input_file, 'r') as file:
        message = file.read()

    encrypted_message = ''
    key_index = 0

    for char in message:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            if char.isupper():
                encrypted_char = chr(((ord(char) - ord('A') + shift) % 26) + ord('A'))
            else:
                encrypted_char = chr(((ord(char) - ord('a') + shift) % 26) + ord('a'))
            key_index += 1
        else:
            encrypted_char = char
        encrypted_message += encrypted_char

    with open(output_file, 'w') as file:
        file.write(encrypted_message)


def auto_key_cipher_encrypt(input_file_path, keyword_file_path):
    try:
        with open(input_file_path, 'r') as input_file:
            message = input_file.read().lower()
    except FileNotFoundError:
        print(f"Input file not found: {input_file_path}")
        return

    try:
        with open(keyword_file_path, 'r') as keyword_file:
            keyword = keyword_file.read().lower()
    except FileNotFoundError:
        print(f"Keyword file not found: {keyword_file_path}")
        return

    keyword = keyword + message  # Extend the keyword to match the length of the message
    keyword = keyword[:len(message)]  # Trim the keyword to match the length of the message

    encrypted_message = ""

    for i in range(len(message)):
        if message[i].isalpha():
            shift = ord(keyword[i]) - ord('a')
            encrypted_char = chr(((ord(message[i]) - ord('a') + shift) % 26) + ord('a'))
            encrypted_message += encrypted_char
        else:
            encrypted_message += message[i]

    try:
        with open("Auto_key3.txt", 'w') as output_file:
            output_file.write(encrypted_message)
    except IOError:
        print(f"Unable to write to the output file: Auto_key.txt")
        
        
def generate_key(message_length, key_file):
    key = [random.randint(0, 255) for _ in range(message_length)]
    with open(key_file, 'wb') as file:
        file.write(bytes(key))

def encrypt(input_file, key_file, output_file):
    with open(input_file, 'rb') as file:
        message = file.read()

    with open(key_file, 'rb') as file:
        key = file.read()

    if len(message) != len(key):
        raise ValueError("Message and key must have the same length")
    
    encrypted_message = bytes([m ^ k for m, k in zip(message, key)])

    with open(output_file, 'wb') as file:
        file.write(encrypted_message)

def decrypt(input_file, key_file, output_file):
    with open(input_file, 'rb') as file:
        encrypted_message = file.read()

    with open(key_file, 'rb') as file:
        key = file.read()

    if len(encrypted_message) != len(key):
        raise ValueError("Ciphertext and key must have the same length")
    
    decrypted_message = bytes([c ^ k for c, k in zip(encrypted_message, key)])

    with open(output_file, 'wb') as file:
        file.write(decrypted_message)
        
# Example usage:
#file_path = "pg33391.txt" #Prwto txt
#file_path = "pg34021.txt" #Deutero txt
file_path = "pg46933.txt" #Trito txt
keyword = "keyword"
keyword_path = "keyword.txt"
keyword_OTP_path = "key_OTP.txt"
#letter_counts = getLetterCount(file_path)
#character_count = countCharactersInFile(file_path)

#A erwtima
#saveLetterFrequencyToCSV(file_path,"letter_frequency3.csv",character_count)

#Ilopoiisi Encoding
#polybius_encode(file_path)
#caesar_cipher_encode(file_path,shift = 13)
#monoalphabetic_cipher(file_path)
#playfair_cipher_encode_from_file(file_path, keyword)
#vigenere_cipher_encrypt_from_file(file_path,keyword)
#running_key_encrypt(file_path,keyword,"Running_key2.txt")
#auto_key_cipher_encrypt(file_path,keyword_path)

#with open(file_path, 'rb') as file:
 #   message_length = len(file.read())

#generate_key(message_length,"key_OTP.bin")
#encrypt(file_path,"key_OTP.bin","OTP3.txt")

#Count characters
temp_filepath = "Playfair3.txt"
temp = getLetterCount(temp_filepath)

charnumber = countCharactersInFile(temp_filepath)

result = {key: (value / charnumber)*100 for key, value in temp.items()}

 
with open("FrequencyDistrPlayfair_Encode3.txt", 'w') as file:
     for key, value in result.items():
         file.write(f"{key}: {value}\n")

#plotLetterFrequency(temp)

