# Kerrious47

File Encryption and Decryption Tool Built with Argon2 and Chacha20-poly1305

## Description

This project is a file encryption and decryption tool built using Go. It combines Argon2, a secure key derivation function, with ChaCha20-Poly1305, an authenticated encryption algorithm. This combination ensures both the confidentiality and integrity of your data.

- **Password-Based Encryption**: Uses Argon2 to securely derive encryption keys from a password.
- **Authenticated Encryption**: Employs ChaCha20-Poly1305 to encrypt files, providing both encryption and integrity checks.
- **Recursive Directory Traversal**: Encrypts or decrypts files in current directory and all its subdirectories.
- **Simple CLI Interface**: Easy to use command-line interface for encryption and decryption operations.

## Installation

**Clone the Repository**
 
 ```bash
 git clone https://github.com/Kaiser-Zheng/Kerrious47.git
 cd Kerrious47
 ```

**Build the Project**

 ```bash
 go build -o kerrious47 main.go
 ```

## Usage

### Encrypting Files

To encrypt files in current directory:

```bash
./kerrious47 -e
```

### Decrypting Files

To decrypt previously encrypted files:

```bash
./kerrious47 -d
```

## Security Consideration

- **Password Strength**: Ensure that you use a strong and unique password for encryption to maximize security.
- **Backup**: Always keep a backup of your original files before encrypting them.
- **Compatibility**: Only files encrypted by this tool can be decrypted with it.

## Contributing

Contributions are welcome! Feel free to submit a pull request or open an issue if you have any suggestions or improvements.
