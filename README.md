# SecurePass Manager 🔐

A secure, command-line password manager built from scratch in C++ with military-grade encryption.

## Features

- **🔒 Secure Encryption** - AES-256 encryption using libsodium
- **👥 Multi-User Support** - Separate encrypted vaults for each user  
- **💾 Persistent Storage** - Auto-saves passwords to encrypted file
- **🛡️ Master Passwords** - Key derivation with Argon2
- **⚡ Fast Lookups** - Custom hash table with double hashing
- **📝 Clean CLI** - Simple, intuitive command-line interface
---
## Installation

### Prerequisites
- C++17 compiler
- libsodium development libraries

### Linux (Ubuntu/Debian)
```bash
sudo apt-get install libsodium-dev
git clone https://github.com/illegitie/secure_password_manager
cd secure_password_manager
make
./password_manager
```
---
###  Usage
```bash
./password_manager

# Register a new user
> register alice mysecret123

# Login
> login alice mysecret123

# Add a password
> add google alice@gmail.com password123

# Retrieve a password  
> get google alice@gmail.com

# List all passwords
> list

# Remove a password
> remove google alice@gmail.com

# Logout
> logout
```

### File Format
```text
Passwords are stored in data.txt with this secure format:
[USER]
username password_hash encryption_key
[PASSWORDS]
service username encrypted_password_hex
[END_USER]
```

### Technical Details
- Hash Table: Double hashing collision resolution
- Resizing: Automatic growth/shrinking based on load factor
- RAII: Automatic memory management
- Exception Safety: Proper error handling throughout

### 🧑‍💻 Author: illegitie  
Built with ❤️ and C++

