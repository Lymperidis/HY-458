def reverse_columnar_transposition(text, key):
    # Remove spaces from the plaintext and convert it to uppercase
    text = text.replace(" ", "").upper()
    
    # Determine the number of columns based on the key length
    num_columns = len(key)
    
    # Calculate the number of rows needed and add padding if necessary
    num_rows = (len(text) + num_columns - 1) // num_columns
    padding = num_rows * num_columns - len(text)
    text += "X" * padding  # Use 'X' as a padding character
    
    # Initialize an empty grid for the transposition
    grid = [['' for _ in range(num_columns)] for _ in range(num_rows)]
    
    # Fill the grid with the plaintext characters
    for row in range(num_rows):
        for col in range(num_columns):
            grid[row][col] = text[row * num_columns + col]
            
           
    
    # Create a dictionary to map key letters to column indices
    key_indices = {char: index for index, char in enumerate(key)}
    print("This is the grid : ", grid)
    # Rearrange the columns based on the key in reverse order
    sorted_key = ''.join(sorted(key, reverse=True))
    print("This is how the reverse alphabetical order of the key will be :", sorted_key)
    
    
    new_grid = [[grid[row][key_indices[char]] for char in sorted_key] for row in range(num_rows)]
    
    # Read the columns from right to left to obtain the ciphertext
    ciphertext = ''.join([''.join(row) for row in new_grid])
    
    return ciphertext




# Input
plaintext = "FAR OUT IN THE UNCHARTED BACKWATERS"
key = "KEYWORD"

# Encrypt the plaintext
encrypted_text = reverse_columnar_transposition(plaintext, key)

# Output
print("Plaintext:", plaintext)
print("Encrypted Text:", encrypted_text)
