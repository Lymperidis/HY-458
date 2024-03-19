import random

# Create an empty 5x5 array
alphabet_grid = [['' for _ in range(5)] for _ in range(5)]

# List of English alphabet letters
alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

# Shuffle the alphabet to fill the grid randomly
shuffled_alphabet = list(alphabet)
random.shuffle(shuffled_alphabet)

# Fill the grid with the shuffled alphabet
for i in range(5):
    for j in range(5):
        alphabet_grid[i][j] = shuffled_alphabet[i * 5 + j]

# Display the filled 2D array
for row in alphabet_grid:
    print(' '.join(row))

def create_polybius_square():
    # Create the Polybius Square using the filled 2D array
    polybius_square = {}
    for i in range(5):
        for j in range(5):
            letter = alphabet_grid[i][j]
            polybius_square[letter] = str(i + 1) + str(j + 1)
    return polybius_square

def polybius_encode(text, polybius_square):
    # Encode a given text using the Polybius Square
    encoded_text = ""
    for char in text:
        if char.isalpha():
            char = char.upper()  # Convert to uppercase for consistency
            if char == 'J':
                char = 'I'  # Treat 'J' as 'I' as is customary in Polybius Square
            if char in polybius_square:
                encoded_text += polybius_square[char]
            else:
                # If the character is not in the Polybius Square, ignore it
                pass
        else:
            encoded_text += char  # Keep non-alphabet characters as-is
    return encoded_text

# Create the Polybius Square
polybius_square = create_polybius_square()

def polybius_decode(encoded_text, polybius_square):
    # Decode a given Polybius Square encoded text
    decoded_text = ""
    i = 0
    while i < len(encoded_text):
        char = encoded_text[i]
        if char.isdigit():
            # Extract the two-digit pair
            pair = encoded_text[i:i+2]
            i += 2
            for letter, code in polybius_square.items():
                if code == pair:
                    decoded_text += letter
                    break
        else:
            # If the character is not a digit, keep it as-is
            decoded_text += char
            i += 1
    return decoded_text

# Example usage:
text_to_encode = "HELLO WORLD"
encoded_text = polybius_encode(text_to_encode, polybius_square)
print("Encoded text:", encoded_text)

decoded_text = polybius_decode(encoded_text, polybius_square)
print("Decoded text:", decoded_text)