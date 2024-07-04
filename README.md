# Image-encryption-on-WSL

This project demonstrates the encryption and decryption of an image using three encryption algorithms: Ascon, AES-256, and ChaCha20.


# Algorithms Used 
- **Ascon**: TheMatjaz's ASCON library(https://github.com/TheMatjaz/LibAscon) was used for this project.   
- **AES-256**: The AES-256 encryption algorithm was utilized through OpenSSL.  
- **ChaCha20**: The ChaCha20 encryption algorithm was also utilized through OpenSSL.  


# Usage 
- **Compilation**:  
The project was compiled using gcc.  
Add -lssl and -lcrypto options to compile :
```sh

gcc -Wall -o TestChaChaEncrypt TestChaChaEncrypt.c -lssl -lcrypto && ./TestChaChaEncrypt

```
- **Encrypting/decrypting an Image**:  
  -   Ascon: Use the specific library provided in the project.  
  -   AES-256 and ChaCha20: Use the functions provided by  OpenSSL library for encryption.  
