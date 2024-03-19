def reverse_columnar_transposition_decrypt(ciphertext, key):
     # Calculate the number of columns based on the key length
     num_columns = len(key)
    
     # Calculate the number of rows needed
     num_rows = (len(ciphertext) + num_columns - 1) // num_columns
    
     # Determine the number of characters in the last row
     last_row_chars = num_columns - (len(ciphertext) % num_columns) if len(ciphertext) % num_columns != 0 else 0
    
     # Create an empty grid for the transposition
     grid = [['' for _ in range(num_columns)] for _ in range(num_rows)]
    
     # Determine the number of columns in the last row
     last_row_columns = num_columns - last_row_chars
    
     col_index = 0
     row_index = num_rows - 1
    
     for char in reversed(ciphertext):
         grid[row_index][col_index] = char
         row_index -= 1
        
         if row_index < 0:
             row_index = num_rows - 1
             col_index += 1
            
             if col_index >= last_row_columns:
                 row_index = num_rows - 1
    
     # Create a dictionary to map key letters to column indices
     key_indices = {char: index for index, char in enumerate(key)}
     print(key_indices)
     # Rearrange the columns based on the key
     new_grid = [['' for _ in range(num_columns)] for _ in range(num_rows)]
     for col_index, key_char in enumerate(key):
         for row_index in range(num_rows):
             new_grid[row_index][key_indices[key_char]] = grid[row_index][col_index]
    
     # Read the columns from left to right to obtain the plaintext
     plaintext = ''.join([''.join(row) for row in new_grid])
    
     return plaintext

 # Input
ciphertext = "HLOORLWDXOXKX"
key = "KEYWORD"

 # Decrypt the ciphertext
decrypted_text = reverse_columnar_transposition_decrypt(ciphertext, key)

 # Output
print("Ciphertext:", ciphertext)
print("Decrypted Text:", decrypted_text)



