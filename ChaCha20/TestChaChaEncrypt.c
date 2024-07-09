#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHACHA_KEYLEN 32 // 256 bits
#define CHACHA_IVLEN 12 // 96 bits

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int chacha20_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, iv)) handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int chacha20_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, key, iv)) handleErrors();

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) handleErrors();
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
//Pour obtenir le code binaire de l'image
void read_file(const char *filename, unsigned char **buffer, long *file_size) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Erreur accès fichier");
        exit(1);
    }
    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    *buffer = (unsigned char *)malloc(*file_size);
    if (*buffer == NULL) {
        perror("Erreur mémoire");
        fclose(file);
        exit(1);
    }
    fread(*buffer, 1, *file_size, file);
    fclose(file);
}

void write_file(const char *filename, unsigned char *buffer, long file_size) {
    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        perror("Erreur accès fichier");
        exit(1);
    }
    fwrite(buffer, 1, file_size, file);
    fclose(file);
}

int main() {
    const char *input_filename = "blue.tiff";
    const char *encrypted_filename = "chacha_encrypted_image.bin";
    const char *decrypted_filename = "chacha_decrypted_image.tiff";

    unsigned char *plaintext, *ciphertext, *decryptedtext;
    long plaintext_len, ciphertext_len, decryptedtext_len;
    unsigned char key[CHACHA_KEYLEN];
    unsigned char iv[CHACHA_IVLEN];

    read_file(input_filename, &plaintext, &plaintext_len);

    // Generate a random key and IV 
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

   
    ciphertext = (unsigned char *)malloc(plaintext_len);
    if (ciphertext == NULL) {
        perror("Erreur mémoire");
        exit(1);
    }

    //Encryption
    ciphertext_len = chacha20_encrypt(plaintext, plaintext_len, key, iv, ciphertext);

    // Ecriture du texte encrypté dans un fichier
    write_file(encrypted_filename, ciphertext, ciphertext_len);

    
    decryptedtext = (unsigned char *)malloc(plaintext_len);
    if (decryptedtext == NULL) {
        perror("Erreur mémoire");
        exit(1);
    }

    //Décryption
    decryptedtext_len = chacha20_decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);

    // Ecriture du texte décrypté dans un fichier
    write_file(decrypted_filename, decryptedtext, decryptedtext_len);

    
    free(plaintext);
    free(ciphertext);
    free(decryptedtext);

    return 0;
}
