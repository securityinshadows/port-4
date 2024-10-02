"""
Created on Oct, 2024

@author: Ayoub Wahmane/securityinshadows
Copyright (c) <2024> <Ayoub Wahmane>. All rights reserved
"""

import random
import bcrypt
from cryptography.fernet import Fernet, InvalidToken
import os
import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64
import getpass

class PasswordManager:
    SALT_SIZE = 29  # bcrypt default salt size
    KDF_ITERATIONS = 100_000  # PBKDF2 iterations
    PASSWORD_MIN_LENGTH = 8  # Minimum password length
    DATA_FILE = "psdt.json.enc"  # Encrypted JSON file
    KEY_FILE = "encrypted_key_file.enc"  # File to store encryption key

    def __init__(self):
        self.letters = [chr(i) for i in range(97, 123)] + [chr(i) for i in range(65, 91)]  # a-z and A-Z
        self.numbers = [str(i) for i in range(10)]  # 0-9
        self.symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']
        self.passwords = {}
        self.key = None
        self.cipher_suite = None

    def derive_key_from_master_password(self, master_password: str, salt: bytes):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.KDF_ITERATIONS,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

    def encrypt_key(self, master_password):
        key = Fernet.generate_key()
        salt = bcrypt.gensalt()  # Generate a random salt for the password
        derived_key = self.derive_key_from_master_password(master_password, salt)
        cipher_suite = Fernet(derived_key)
        encrypted_key = cipher_suite.encrypt(key)

        try:
            with open(self.KEY_FILE, "wb") as f:
                f.write(salt + encrypted_key)  # Store salt + encrypted key together
        except IOError as e:
            print(f"Error saving encrypted key: {e}")

    def decrypt_key(self, master_password):
        try:
            with open(self.KEY_FILE, "rb") as f:
                file_data = f.read()
            salt = file_data[:self.SALT_SIZE]  # Extract the salt
            encrypted_key = file_data[self.SALT_SIZE:]
            derived_key = self.derive_key_from_master_password(master_password, salt)
            cipher_suite = Fernet(derived_key)
            decrypted_key = cipher_suite.decrypt(encrypted_key)
            return decrypted_key  # Ensure this is a bytes object
        except InvalidToken:
            print("Incorrect master password.")
            return None
        except FileNotFoundError:
            print("Key file not found.")
            return None
        except Exception as e:
            print(f"Error decrypting key: {e}")
            return None

    def load_key(self):
        if not os.path.exists(self.KEY_FILE):
            return None  # Key file doesn't exist yet
        else:
            return self.decrypt_key(getpass.getpass("Enter your master password to log in [WARNING! Input is invisible]: "))

    def load_data(self):
        if os.path.exists(self.DATA_FILE):
            with open(self.DATA_FILE, "rb") as data_file:
                encrypted_data = data_file.read()
            try:
                decrypted_data = self.cipher_suite.decrypt(encrypted_data).decode()
                data = json.loads(decrypted_data)
                self.passwords = data.get("passwords", {})
            except Exception as e:
                print("Error decrypting data:", e)
                self.passwords = {}
        else:
            print("No data file found. Creating a new file...")

    def save_data(self):
        data = {
            "passwords": self.passwords
        }
        json_data = json.dumps(data).encode()
        encrypted_data = self.cipher_suite.encrypt(json_data)
        try:
            with open(self.DATA_FILE, "wb") as data_file:
                data_file.write(encrypted_data)
        except IOError as e:
            print(f"Error saving data file: {e}")

    def reset_manager(self):
        if os.path.exists(self.KEY_FILE):
            os.remove(self.KEY_FILE)
        if os.path.exists(self.DATA_FILE):
            os.remove(self.DATA_FILE)
        print("Password manager reset. You can now set a new master password.")

    def random_prompt(self):
        while True:
            length = input("Password Length: ")
            if length.isdigit() and int(length) >= self.PASSWORD_MIN_LENGTH:
                return int(length)
            else:
                print(f"Please enter a valid number (minimum length {self.PASSWORD_MIN_LENGTH}).")

    def password_generator(self, length):
        return ''.join(random.choices(self.letters + self.numbers + self.symbols, k=length))

    def add_password(self):
        site = input("Enter the site name: ")
        if site in self.passwords:
            print("Password already exists for this site. Please choose another site.")
            return
        pass_choice = input("1 - Add password\n2 - Generate password\nEnter your choice: ")
        if pass_choice == '1':
            password = input("Password: ")
            self.passwords[site] = password
            print(f"Password for {site} added.")
        elif pass_choice == '2':
            length = self.random_prompt()
            password = self.password_generator(length)
            self.passwords[site] = password
            print(f"Password for {site} generated: {password}")
        else:
            print("Invalid choice.")

    def search_password(self):
        site = input("Enter site name to search: ")
        if site in self.passwords:
            print(f"Site: {site}, Password: {self.passwords[site]}")
        else:
            print("Site not found.")

    def main_menu(self):
        while True:
            print("\nMain Menu")
            print("1 - Add Password")
            print("2 - Search Password")
            print("3 - Reset Password Manager")
            print("4 - Exit")
            choice = input("Enter your choice: ")
            if choice == '1':
                self.add_password()
                self.save_data()
            elif choice == '2':
                self.search_password()
            elif choice == '3':
                confirmation = input("Are you sure you want to reset? This will delete all saved data. (y/n): ")
                if confirmation.lower() == 'y':
                    self.reset_manager()
                    break
            elif choice == '4':
                print("Exiting... Goodbye!")
                break
            else:
                print("Invalid choice. Please try again.")

    def login(self):
        while True:
            print("1 - Log in")
            print("2 - Reset Password Manager")
            choice = input("Enter your choice: ")
            if choice == '1':
                self.key = self.load_key()
                if self.key is not None:
                    self.cipher_suite = Fernet(self.key)
                    self.load_data()
                    break
                else:
                    print("Invalid master password or key.")
            elif choice == '2':
                self.reset_manager()
                break
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    manager = PasswordManager()

    # Start with login or reset option
    manager.login()

    if manager.key is None:  # Key is None if the user chose to reset
        while True:
            master_password = getpass.getpass("Set a new master password [WARNING! Input is invisible]: ")
            confirm_password = getpass.getpass("Confirm the new master password [WARNING! Input is invisible]: ")
            if master_password == confirm_password:
                manager.encrypt_key(master_password)
                manager.key = manager.decrypt_key(master_password)
                manager.cipher_suite = Fernet(manager.key)
                break
            else:
                print("Passwords do not match. Please try again.")

    # Proceed to main menu
    manager.main_menu()

