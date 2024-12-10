# Password Manager

A simple yet secure password manager built using Java. This tool allows you to securely store and retrieve login credentials for various websites. The passwords are encrypted using AES (Advanced Encryption Standard) before storing them, and PBKDF2 (Password-Based Key Derivation Function 2) is used to derive a secure key from your master password.

## Features

- **Master Password**: Set a master password to access your password manager.
- **Password Encryption**: Passwords are encrypted using AES and securely stored.
- **Key Derivation**: PBKDF2 is used to derive a strong encryption key from your master password.
- **Secure Storage**: Credentials are stored in an encrypted text file.
- **Retrieve Credentials**: Retrieve and decrypt stored credentials using the website's name.

## Technologies Used

- **Java**: The programming language used to build the application.
- **AES Encryption**: For securely encrypting passwords.
- **PBKDF2**: To securely derive an encryption key from the master password.
- **Base64 Encoding**: To encode encrypted data into a storable format.
