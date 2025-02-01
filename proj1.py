import numpy as np
from tkinter import Tk, Label, Button, Text, OptionMenu, StringVar, Entry, messagebox
import tkinter as tk
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import random
import math
import string


class EncryptionGUI:
    def __init__(self, master):
        self.master = master
        master.title("Encryption/Decryption")

        self.label = Label(master, text="Encryption/Decryption", font=("Arial", 18, "bold"))
        self.label.grid(row=0, column=0, columnspan=3, pady=10)

        self.cipher_type_label = Label(master, text="Select Encryption Method:", font=("Arial", 12))
        self.cipher_type_label.grid(row=1, column=0, columnspan=3, padx=10, pady=5)

        self.cipher_type = StringVar(master)
        self.cipher_type.set("RSA")  # Default selection
        self.cipher_menu = OptionMenu(master, self.cipher_type, "RSA", "Hill", "Monoalphabetic","CeaserCipher","Polyalphabetic","PlayfairCipher","OneTimePad","RailFenceCipher",)
        self.cipher_menu.grid(row=2, column=0, columnspan=3, padx=10, pady=5, sticky="ew")
        

        self.generate_key_button = Button(master, text="Generate Key", command=self.generate_key)
        self.generate_key_button.grid(row=3, column=0, padx=10, pady=5, sticky="ew")

        self.encrypt_button = Button(master, text="Encrypt", command=self.encrypt)
        self.encrypt_button.grid(row=3, column=1, padx=10, pady=5, sticky="ew")

        self.decrypt_button = Button(master, text="Decrypt", command=self.decrypt)
        self.decrypt_button.grid(row=3, column=2, padx=10, pady=5, sticky="ew")

        self.textbox_label = Label(master, text="Enter Text:", font=("Arial", 12))
        self.textbox_label.grid(row=4, column=0, columnspan=3, padx=10, pady=5)

        self.textbox = Text(master, height=5, width=50, font=("Arial", 12))
        self.textbox.grid(row=5, column=0, columnspan=3, padx=10, pady=5)

        self.result_label = Label(master, text="", font=("Arial", 12), fg="green")
        self.result_label.grid(row=6, column=0, columnspan=3, padx=10, pady=5)
        
        self.mono_cipher = MonoalphabeticCipher()
        self.ceaser_cipher = CaesarCipher(4)
        self.polyalphabetic = Polyalphabetic ("PASSWORD")
        self.playfair = PlayfairCipher("PASSWORD")
        self.onetimepad = OneTimePad("PASSWORD")
        self.railfence = RailFenceCipher(rails=3)
        #self.hillcipher = HillCipher()


    def generate_key(self):
        if self.cipher_type.get() == "RSA":
            self.key = RSA.generate(2048)
            messagebox.showinfo("Key Generated", "RSA Key Generated Successfully")
        if self.cipher_type.get() == "HillCipher":
            self.key = np.random.randint(0, 26, (3, 3))
            while np.linalg.det(self.key) == 0: self.key = np.random.randint(0, 26, (3, 3))
            messagebox.showinfo("Key Generated", "Hillcipher Key Generated Successfully")

        if self.cipher_type.get() == "Monoalphabetic":
            
            # Generate a shuffled alphabet
            original_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            shuffled_alphabet = list(original_alphabet)
            random.shuffle(shuffled_alphabet)
            self.key = dict(zip(original_alphabet, shuffled_alphabet))
            print("Monoalphabetic generated key: ",self.key,"Length : ",len(self.key))
            messagebox.showinfo("Key Generated", "Monoalphabetic Key Generated Successfully")
        

    def generate_random_key(self,length):
        return ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(length))


    def encrypt(self):
        if not hasattr(self, 'key') and (self.cipher_type.get() == "RSA" or self.cipher_type.get() == "Monoalphebatic"):
            messagebox.showerror("Error", "Key pair not generated. Please generate key pair.")
            return

        if self.cipher_type.get() == "RSA":
            # RSA Encryption
            public_key = self.key.publickey()
            cipher = PKCS1_OAEP.new(public_key)
            plaintext = self.textbox.get("1.0", "end-1c").encode('utf-8')
            encrypted_text = cipher.encrypt(plaintext)
            self.textbox.delete("1.0", "end")
            self.textbox.insert("1.0", encrypted_text.hex())
            self.result_label.config(text="RSA Encryption Successful", fg="green")
        if self.cipher_type.get() == "HILL":
            messagebox.showerror("implementation pending")
        if self.cipher_type.get() == "Monoalphabetic":
            key = self.key
            print("Passed Key : ",key)
            if not self.mono_cipher.set_key(key):
                return
            plaintext = self.textbox.get("1.0", "end-1c")
            print("plaintext from textbox : ",plaintext)
            ciphertext = self.mono_cipher.encrypt(plaintext)
            self.textbox.delete("1.0", "end")
            self.textbox.insert("1.0", ciphertext)
            self.result_label.config(text="Monoalphabetic Encryption Successful", fg="green")
        if self.cipher_type.get() == "CeaserCipher": 
            plaintext=self.textbox.get("1.0", "end-1c")
            ciphertext = self.ceaser_cipher.encrypt(plaintext)
            self.textbox.delete("1.0", "end")
            self.textbox.insert("1.0", ciphertext)
            self.result_label.config(text="CeaserCipher Encryption Successful", fg="green")
        if self.cipher_type.get() == "Polyalphabetic": 
            plaintext=self.textbox.get("1.0", "end-1c")
            ciphertext = self.polyalphabetic.encrypt(plaintext)
            self.textbox.delete("1.0", "end")
            self.textbox.insert("1.0", ciphertext)
            self.result_label.config(text="Polyalphabetic Encryption Successful", fg="green")
        if self.cipher_type.get() == "PlayfairCipher": 
            plaintext=self.textbox.get("1.0", "end-1c")
            ciphertext = self.playfair.encrypt(plaintext)
            self.textbox.delete("1.0", "end")
            self.textbox.insert("1.0", ciphertext)
            self.result_label.config(text="PlayfairCipher Encryption Successful", fg="green")
        if self.cipher_type.get() == "OneTimePad":
            plaintext=self.textbox.get("1.0", "end-1c")
            random_key = self.generate_random_key(len(plaintext))            
            self.onetimepad = OneTimePad(random_key)
            ciphertext = self.onetimepad.encrypt(plaintext)
            self.textbox.delete("1.0", "end")
            self.textbox.insert("1.0", ciphertext)
            self.result_label.config(text="OneTimePad Encryption Successful", fg="green")
        if self.cipher_type.get() == "RailFenceCipher": 
            plaintext=self.textbox.get("1.0", "end-1c")
            ciphertext = self.railfence.encrypt(plaintext)
            self.textbox.delete("1.0", "end")
            self.textbox.insert("1.0", ciphertext)
            self.result_label.config(text="RailFenceCipher Encryption Successful", fg="green")
        

    def decrypt(self):
        if not hasattr(self, 'key') and (self.cipher_type.get() == "RSA" or self.cipher_type.get() == "Monoalphebatic"):
            messagebox.showerror("Error", "Key pair not generated. Please generate key pair.")
            return

        if self.cipher_type.get() == "RSA":
            # RSA Decryption
            private_key = self.key
            cipher = PKCS1_OAEP.new(private_key)
            encrypted_text = bytes.fromhex(self.textbox.get("1.0", "end-1c"))
            decrypted_text = cipher.decrypt(encrypted_text).decode('utf-8')
            self.textbox.delete("1.0", "end")
            self.textbox.insert("1.0", decrypted_text)
            self.result_label.config(text="RSA Decryption Successful", fg="green")
        if self.cipher_type.get() == "HILL":
            messagebox.showerror("implementation pending")

        if self.cipher_type.get() == "Monoalphabetic":
            key = self.key
            if not self.mono_cipher.set_key(key):
                return
            ciphertext = self.textbox.get("1.0", "end-1c")
            plaintext = self.mono_cipher.decrypt(ciphertext)
            self.textbox.delete("1.0", "end")
            self.textbox.insert("1.0", plaintext)
            self.result_label.config(text="Monoalphabetic Decryption Successful", fg="green")
        if self.cipher_type.get() == "CeaserCipher":
            ciphertext = self.textbox.get("1.0", "end-1c")
            plaintext = self.ceaser_cipher.decrypt(ciphertext)
            self.textbox.delete("1.0", "end")
            self.textbox.insert("1.0", plaintext)
            self.result_label.config(text="CeaserCipher Decryption Successful", fg="green")
        if self.cipher_type.get() == "Polyalphabetic":
            ciphertext = self.textbox.get("1.0", "end-1c")
            plaintext = self.polyalphabetic.decrypt(ciphertext)
            self.textbox.delete("1.0", "end")
            self.textbox.insert("1.0", plaintext)
            self.result_label.config(text="Polyalphabetic Decryption Successful", fg="green")
        if self.cipher_type.get() == "PlayfairCipher":
            ciphertext = self.textbox.get("1.0", "end-1c")
            plaintext = self.playfair.decrypt(ciphertext)
            self.textbox.delete("1.0", "end")
            self.textbox.insert("1.0", plaintext)
            self.result_label.config(text="PlayfairCipher Decryption Successful", fg="green")
        if self.cipher_type.get() == "OneTimePad":
            ciphertext = self.textbox.get("1.0", "end-1c")
            plaintext = self.onetimepad.decrypt(ciphertext)
            self.textbox.delete("1.0", "end")
            self.textbox.insert("1.0", plaintext)
            self.result_label.config(text="OneTimePad Decryption Successful", fg="green")
        if self.cipher_type.get() == "RailFenceCipher":
            ciphertext = self.textbox.get("1.0", "end-1c")
            plaintext = self.railfence.decrypt(ciphertext)
            self.textbox.delete("1.0", "end")
            self.textbox.insert("1.0", plaintext)
            self.result_label.config(text="RailFenceCipher Decryption Successful", fg="green")
        if self.cipher_type.get() == "HillCipher":
            ciphertext = self.textbox.get("1.0", "end-1c")
            plaintext = self.hillcipher.decrypt(ciphertext)
            self.textbox.delete("1.0", "end")
            self.textbox.insert("1.0", plaintext)
            self.result_label.config(text="HillCipher Decryption Successful", fg="green")

class HillCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        # Ensure the plaintext length is a multiple of the key matrix size
        while len(plaintext) % len(self.key) != 0:
            plaintext += 'X'  # Padding with 'X'

        # Convert the plaintext characters to numbers
        plaintext_numbers = [ord(char) - ord('A') for char in plaintext]

        # Reshape the plaintext numbers into a matrix
        plaintext_matrix = np.array(plaintext_numbers).reshape(-1, len(self.key))

        # Convert the key characters to numbers
        key_numbers = [ord(char) - ord('A') for char in self.key]

        # Reshape the key numbers into a matrix
        key_matrix = np.array(key_numbers).reshape(len(self.key), len(self.key))

        # Encrypt the plaintext by matrix multiplication
        encrypted_matrix = np.dot(plaintext_matrix, key_matrix) % 26

        # Convert the encrypted matrix back to characters
        encrypted_text = ''.join([chr(num + ord('A')) for row in encrypted_matrix for num in row])

        return encrypted_text

    def decrypt(self, ciphertext):
        # Convert the ciphertext characters to numbers
        ciphertext_numbers = [ord(char) - ord('A') for char in ciphertext]

        # Reshape the ciphertext numbers into a matrix
        ciphertext_matrix = np.array(ciphertext_numbers).reshape(-1, len(self.key))

        # Calculate the modular inverse of the key matrix
        key_matrix_inverse = np.linalg.inv(np.array(self.key)).astype(int)
        det = int(np.round(np.linalg.det(key_matrix_inverse)))
        det_inv = pow(det, -1, 26)

        # Multiply the ciphertext matrix by the inverse of the key matrix
        decrypted_matrix = np.dot(ciphertext_matrix, key_matrix_inverse) * det_inv % 26

        # Convert the decrypted matrix back to characters
        decrypted_text = ''.join([chr(int(num) + ord('A')) for row in decrypted_matrix for num in row])

        return decrypted_text

  
class MonoalphabeticCipher:
    def __init__(self):
        self.alphabet = string.ascii_uppercase
        self.key = None

    def set_key(self, key=None):
        if key is None:
            key = dict(zip(self.alphabet, random.sample(self.alphabet, len(self.alphabet))))
        else:
            if len(key) != 26 or not all(k.isalpha() and v.isalpha() for k, v in key.items()) or len(set(key.values())) != 26:
                messagebox.showerror("Error", "Invalid key. Key must be a permutation of the alphabet.")
                return False
        self.key = {k: v.upper() for k, v in key.items()}
        return True

    def encrypt(self, plaintext):
        if self.key is None:
            messagebox.showerror("Error", "Key not set.")
            return None

        plaintext = plaintext.upper()
        ciphertext = ""
        for char in plaintext:
            if char.isalpha():
                ciphertext += self.key[char]
            else:
                ciphertext += char
        return ciphertext

    def decrypt(self, ciphertext):
        if self.key is None:
            messagebox.showerror("Error", "Key not set.")
            return None

        ciphertext = ciphertext.upper()
        plaintext = ""
        for char in ciphertext:
            if char.isalpha():
                for k, v in self.key.items():
                    if v == char:
                        plaintext += k
                        break
            else:
                plaintext += char
        return plaintext
class CaesarCipher:
    def __init__(self, shift):
        self.alphabet = string.ascii_uppercase
        self.shift = shift

    def encrypt(self, plaintext):
        ciphertext = ""
        for char in plaintext:
            if char.isalpha():
                shifted_index = (self.alphabet.index(char.upper()) + self.shift) % 26
                shifted_char = self.alphabet[shifted_index]
                if char.islower():
                    shifted_char = shifted_char.lower()
                ciphertext += shifted_char
            else:
                ciphertext += char
        return ciphertext

    def decrypt(self, ciphertext):
        plaintext = ""
        for char in ciphertext:
            if char.isalpha():
                shifted_index = (self.alphabet.index(char.upper()) - self.shift) % 26
                shifted_char = self.alphabet[shifted_index]
                if char.islower():
                    shifted_char = shifted_char.lower()
                plaintext += shifted_char
            else:
                plaintext += char
        return plaintext

class Polyalphabetic:
    def __init__(self, key):
        self.key = key.upper()
        self.alphabet = string.ascii_uppercase

    def extend_key(self, plaintext):
        extended_key = ""
        key_length = len(self.key)
        for i in range(len(plaintext)):
            extended_key += self.key[i % key_length]
        return extended_key

    def encrypt(self, plaintext):
        plaintext = plaintext.upper()
        extended_key = self.extend_key(plaintext)
        ciphertext = ""
        for i in range(len(plaintext)):
            if plaintext[i].isalpha():
                shift = self.alphabet.index(extended_key[i])
                shifted_index = (self.alphabet.index(plaintext[i]) + shift) % 26
                ciphertext += self.alphabet[shifted_index]
            else:
                ciphertext += plaintext[i]
        return ciphertext

    def decrypt(self, ciphertext):
        ciphertext = ciphertext.upper()
        extended_key = self.extend_key(ciphertext)
        plaintext = ""
        for i in range(len(ciphertext)):
            if ciphertext[i].isalpha():
                shift = self.alphabet.index(extended_key[i])
                shifted_index = (self.alphabet.index(ciphertext[i]) - shift) % 26
                plaintext += self.alphabet[shifted_index]
            else:
                plaintext += ciphertext[i]
        return plaintext
    
    
class PlayfairCipher:
    def __init__(self, keyword):
        self.keyword = self.prepare_keyword(keyword)
        self.playfair_square = self.generate_playfair_square(self.keyword)

    def generate_playfair_square(self):
        # Create a list to store the 5x5 grid (Playfair square)
        self.playfair_square = [['' for _ in range(5)] for _ in range(5)]
        # Fill the Playfair square with unique letters from the keyword
        letters = []
        for char in self.keyword:
            if char not in letters and char != 'J':
                letters.append(char)
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        index = 0
        for row in range(5):
            for col in range(5):
                if index < len(letters):
                    self.playfair_square[row][col] = letters[index]
                    index += 1
                else:
                    for letter in alphabet:
                        if letter not in letters and letter != 'J':
                            self.playfair_square[row][col] = letter
                            letters.append(letter)
                            break

    def print_playfair_square(self):
        for row in self.playfair_square:
            print(" ".join(row))
    
    def prepare_keyword(self, keyword):
        # Remove duplicate letters from the keyword and append the remaining letters of the alphabet
        keyword = ''.join(dict.fromkeys(keyword.upper()))
        alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
        for char in alphabet:
            if char not in keyword:
                keyword += char
        return keyword

    def generate_playfair_square(self, keyword):
        # Generate the Playfair square based on the keyword
        playfair_square = [['' for _ in range(5)] for _ in range(5)]
        index = 0
        for i in range(5):
            for j in range(5):
                playfair_square[i][j] = keyword[index]
                index += 1
        return playfair_square

    def find_char_position(self, char):
        # Find the position of a character in the Playfair square
        for i in range(5):
            for j in range(5):
                if self.playfair_square[i][j] == char:
                    return i, j

    def encrypt(self, plaintext):
        # Encrypt plaintext using the Playfair cipher
        plaintext = plaintext.upper().replace('J', 'I')  # Replace 'J' with 'I'
        ciphertext = ''
        for i in range(0, len(plaintext), 2):
            char1, char2 = plaintext[i], ''
            if i + 1 < len(plaintext):
                char2 = plaintext[i + 1]
            row1, col1 = self.find_char_position(char1)
            row2, col2 = self.find_char_position(char2)
            if row1 == row2:  # Same row
                ciphertext += self.playfair_square[row1][(col1 + 1) % 5]
                ciphertext += self.playfair_square[row2][(col2 + 1) % 5]
            elif col1 == col2:  # Same column
                ciphertext += self.playfair_square[(row1 + 1) % 5][col1]
                ciphertext += self.playfair_square[(row2 + 1) % 5][col2]
            else:  # Rectangle
                ciphertext += self.playfair_square[row1][col2]
                ciphertext += self.playfair_square[row2][col1]
        return ciphertext

    def decrypt(self, ciphertext):
        # Decrypt ciphertext using the Playfair cipher
        plaintext = ''
        for i in range(0, len(ciphertext), 2):
            char1, char2 = ciphertext[i], ciphertext[i + 1]
            row1, col1 = self.find_char_position(char1)
            row2, col2 = self.find_char_position(char2)
            if row1 == row2:  # Same row
                plaintext += self.playfair_square[row1][(col1 - 1) % 5]
                plaintext += self.playfair_square[row2][(col2 - 1) % 5]
            elif col1 == col2:  # Same column
                plaintext += self.playfair_square[(row1 - 1) % 5][col1]
                plaintext += self.playfair_square[(row2 - 1) % 5][col2]
            else:  # Rectangle
                plaintext += self.playfair_square[row1][col2]
                plaintext += self.playfair_square[row2][col1]
        return plaintext
class OneTimePad:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        # Ensure the key length matches the plaintext length
        if len(self.key) != len(plaintext):
            raise ValueError("Key length must match plaintext length.")
        
        # Convert plaintext and key to binary strings
        plaintext_bin = ''.join(format(ord(char), '08b') for char in plaintext)
        key_bin = ''.join(format(ord(char), '08b') for char in self.key)

        # Perform bitwise XOR operation
        ciphertext_bin = ''.join('1' if bit1 != bit2 else '0' for bit1, bit2 in zip(plaintext_bin, key_bin))

        # Convert binary string to ciphertext
        ciphertext = ''.join(chr(int(ciphertext_bin[i:i+8], 2)) for i in range(0, len(ciphertext_bin), 8))
        return ciphertext

    def decrypt(self, ciphertext):
        # Ensure the key length matches the ciphertext length
        if len(self.key) != len(ciphertext):
            raise ValueError("Key length must match ciphertext length.")
        
        # Convert ciphertext and key to binary strings
        ciphertext_bin = ''.join(format(ord(char), '08b') for char in ciphertext)
        key_bin = ''.join(format(ord(char), '08b') for char in self.key)

        # Perform bitwise XOR operation
        plaintext_bin = ''.join('1' if bit1 != bit2 else '0' for bit1, bit2 in zip(ciphertext_bin, key_bin))

        # Convert binary string to plaintext
        plaintext = ''.join(chr(int(plaintext_bin[i:i+8], 2)) for i in range(0, len(plaintext_bin), 8))
        return plaintext
class RailFenceCipher:
    def __init__(self, rails):
        self.rails = rails

    def encrypt(self, plaintext):
        fence = [[] for _ in range(self.rails)]
        rail = 0
        direction = 1

        for char in plaintext:
            fence[rail].append(char)
            rail += direction

            if rail == self.rails - 1 or rail == 0:
                direction *= -1

        ciphertext = ''.join([''.join(rail) for rail in fence])
        return ciphertext

    def decrypt(self, ciphertext):
        fence = [[] for _ in range(self.rails)]
        rail = 0
        direction = 1

        # Fill the fence with placeholders
        for i in range(len(ciphertext)):
            fence[rail].append(None)
            rail += direction

            if rail == self.rails - 1 or rail == 0:
                direction *= -1

        # Replace placeholders with characters from ciphertext
        index = 0
        for i in range(self.rails):
            for j in range(len(fence[i])):
                if fence[i][j] is None:
                    fence[i][j] = ciphertext[index]
                    index += 1

        # Read off the plaintext
        rail = 0
        direction = 1
        plaintext = ''
        for _ in range(len(ciphertext)):
            plaintext += fence[rail][0]
            del fence[rail][0]
            rail += direction

            if rail == self.rails - 1 or rail == 0:
                direction *= -1

        return plaintext

root = Tk()
my_gui = EncryptionGUI(root)
root.mainloop()
