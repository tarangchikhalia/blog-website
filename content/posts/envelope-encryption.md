---
date: '2024-12-24T13:43:12-04:00'
draft: false
title: 'Envelope Encryption: A secure approach to secret management.'
tags: ["security", "encryption"]
categories: ["security"]
---

In the modern software development landscape, applications frequently rely on secrets like passwords, API keys, or tokens to access external services and data. Ensuring these secrets are stored securely is paramount, as improper handling can lead to severe security breaches. Envelope encryption provides a robust mechanism for managing and securing these secrets, offering a layered approach to encryption.

This blog will delve into the principles of envelope encryption and illustrate how to implement it using Python, based on the Secure Secrets project files.

## Understanding Envelope Encryption
Envelope encryption operates on a multi-layered security architecture, combining multiple keys to safeguard sensitive data. The layers include:

**Master Key**: A root key stored in a secure location such as a Key Management Service (KMS) or Hardware Security Module (HSM). This key derives other keys.

**Key Encryption Key (KEK)**: A key derived from the Master Key using a cryptographic function. It encrypts and decrypts the Data Encryption Key (DEK).

**Data Encryption Key (DEK)**: A randomly generated key used to encrypt and decrypt the actual data (secrets).

## Workflow of Envelope Encryption
The process of envelope encryption involves:

* Generating a KEK from the Master Key and a unique salt.
* Creating a DEK for each secret.
* Encrypting the DEK using the KEK.
* Using the DEK to encrypt sensitive data.
* The KEK and DEK layers ensure that even if one layer is compromised, the other provides a fallback security measure.

## Python Implementation of Envelope Encryption
The provided Python implementation uses the cryptography library to handle key derivation, encryption, and decryption. Let’s explore its key components.

1. **Key Management Class**
The KeyManagement class initializes the encryption process and manages Master Keys, KEKs, and DEKs.
```
class KeyManagement:
    def __init__(self, project_unique_str: str):
        self.project_unique_str = project_unique_str
        self.master_key = "SECRET_MASTER_KEY"
```
Here, the master_key is the root key, and project_unique_str ensures project-specific uniqueness.

**NOTE: For simplicity, the master_key is hardcoded but it is highly recommended that the master_key is stored in a secure location.**

2. **Generating KEKs**
KEKs are derived using a key derivation function (KDF) and a random salt.
```
def generate_kek(self) -> Tuple[bytes, bytes]:
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    kek = base64.urlsafe_b64encode(kdf.derive((self.master_key + self.project_unique_str).encode()))
    return kek, salt
```
The PBKDF2HMAC function strengthens the KEK derivation by applying multiple hash iterations.

3. **Creating and Encrypting DEKs**
A DEK is generated randomly for each secret, and then encrypted using the KEK.
```
def generate_dek(self) -> bytes:
    return Fernet.generate_key()

def encrypt_dek(self, dek: bytes, kek: bytes) -> bytes:
    fernet = Fernet(kek)
    return fernet.encrypt(dek)
```
The encrypted DEK ensures the actual secret encryption key is not exposed directly.

4. **Data Encryption and Decryption**
The DEK encrypts and decrypts application secrets securely.
```
def encrypt_data(self, data: str, dek: bytes) -> bytes:
    fernet = Fernet(dek)
    return fernet.encrypt(data.encode())

def decrypt_data(self, encrypted_data: bytes, dek: bytes) -> str:
    fernet = Fernet(dek)
    return fernet.decrypt(encrypted_data).decode()
```

## Sample Usage
The following snippet demonstrates the initialization of the encryption system and securing a secret:
```
key_mgmt = KeyManagement("unique_project_id")

# Initialize the encryption process
encrypted_dek, salt = key_mgmt.initialize()

# Generate KEK using the saved salt
kek, _ = key_mgmt.generate_kek()

# Secure a secret
dek = key_mgmt.decrypt_dek(encrypted_dek, kek)
encrypted_secret = key_mgmt.encrypt_data("my_password", dek)

# Retrieve the secret
decrypted_secret = key_mgmt.decrypt_data(encrypted_secret, dek)
print("Decrypted Secret:", decrypted_secret)
```

## Advantages of Envelope Encryption
* **Scalability**: Secrets for multiple applications or environments (Dev, Staging, Prod) can be managed securely using different DEKs, all derived from the same Master Key.

* **Security**: Even if a DEK is exposed, it cannot be decrypted without the KEK.

* **Compliance**: Many regulatory frameworks recommend or mandate layered encryption approaches like envelope encryption.

## Conclusion
Envelope encryption is a gold standard for secure secrets management. By layering Master Keys, KEKs, and DEKs, it minimizes the risk of exposing sensitive data. The Python implementation described here provides a practical framework for adopting envelope encryption in your projects.
