import json
import re
import random
import string

# Caesar cipher encryption and decryption functions (pre-implemented)
def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# Password strength checker function (optional)
def is_strong_password(password):
    """
    Check if the password is strong: at least 8 characters, 
    includes uppercase, lowercase, digit, and special character.
    """
    if (len(password) >= 8 and
        re.search(r'[A-Z]', password) and
        re.search(r'[a-z]', password) and
        re.search(r'\d', password) and
        re.search(r'[!@#$%^&*(),.?":{}|<>]', password)):
        return True
    else:
        return False

# Password generator function (optional)
def generate_password(length):
    """
    Generate a random strong password of the specified length.
    """
    if length < 8:
        print("Password too short. Must be at least 8 characters.")
        return None

    all_chars = string.ascii_letters + string.digits + "!@#$%^&*(),.?\":{}|<>"
    password = ''.join(random.choice(all_chars) for _ in range(length))
    return password

# Initialize empty lists to store encrypted passwords, websites, and usernames
encrypted_passwords = []
websites = []
usernames = []

# Function to add a new password 
def add_password():
    """
    Add a new password to the password manager.
    """
    website = input("Enter website: ")
    username = input("Enter username: ")
    
    choice = input("Do you want to (1) enter your own password or (2) generate a strong password? Enter 1 or 2: ")
    
    if choice == "1":
        password = input("Enter password: ")
        if not is_strong_password(password):
            print("Warning: Your password is not strong enough!")
    elif choice == "2":
        length = int(input("Enter desired password length (at least 8): "))
        password = generate_password(length)
        if password:
            print(f"Generated password: {password}")
        else:
            return
    else:
        print("Invalid choice.")
        return

    encrypted = caesar_encrypt(password, shift=3)  # simple Caesar encryption with shift 3
    websites.append(website)
    usernames.append(username)
    encrypted_passwords.append(encrypted)
    print(f"Password for {website} added successfully!")

# Function to retrieve a password 
def get_password():
    """
    Retrieve a password for a given website.
    """
    website = input("Enter website name to retrieve password: ")
    if website in websites:
        index = websites.index(website)
        username = usernames[index]
        encrypted = encrypted_passwords[index]
        password = caesar_decrypt(encrypted, shift=3)
        print(f"Username: {username}")
        print(f"Password: {password}")
    else:
        print("Website not found.")

# Function to save passwords to a JSON file 
def save_passwords():
    """
    Save the password vault to a file.
    """
    vault = []
    for i in range(len(websites)):
        entry = {
            "website": websites[i],
            "username": usernames[i],
            "password": encrypted_passwords[i]  # save encrypted password
        }
        vault.append(entry)
    with open("vault.txt", "w") as f:
        json.dump(vault, f)
    print("Passwords saved successfully!")

# Function to load passwords from a JSON file 
def load_passwords():
    """
    Load passwords from a file into the password vault.
    """
    global websites, usernames, encrypted_passwords
    try:
        with open("vault.txt", "r") as f:
            vault = json.load(f)
            websites = []
            usernames = []
            encrypted_passwords = []
            for entry in vault:
                websites.append(entry["website"])
                usernames.append(entry["username"])
                encrypted_passwords.append(entry["password"])
    except FileNotFoundError:
        print("Vault file not found. Starting with empty password vault.")

# Main method
def main():
    while True:
        print("\nPassword Manager Menu:")
        print("1. Add Password")
        print("2. Get Password")
        print("3. Save Passwords")
        print("4. Load Passwords")
        print("5. Quit")
        
        choice = input("Enter your choice: ")
        
        if choice == "1":
            add_password()
        elif choice == "2":
            get_password()
        elif choice == "3":
            save_passwords()
        elif choice == "4":
            load_passwords()
            print("Passwords loaded successfully!")
        elif choice == "5":
            break
        else:
            print("Invalid choice. Please try again.")

# Execute the main function when the program is run
if __name__ == "__main__":
    main()