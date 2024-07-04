#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AES_KEYLEN 32 // 256 bits
#define AES_GCM_IVLEN 12 // 96 bits
#define AES_GCM_TAGLEN 16 // 128 bits

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int aes_gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad, int aad_len,
                    unsigned char *key, unsigned char *iv, int iv_len,
                    unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAGLEN, tag)) handleErrors();

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aes_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad, int aad_len,
                    unsigned char *tag, unsigned char *key, unsigned char *iv, int iv_len,
                    unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) handleErrors();

    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) handleErrors();

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) handleErrors();
    plaintext_len = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAGLEN, tag)) handleErrors();

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
        return -1;
    }
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
    const char *encrypted_filename = "encrypted_image.bin";
    const char *decrypted_filename = "decrypted_image.tiff";

    unsigned char *plaintext, *ciphertext, *decryptedtext;
    long plaintext_len, ciphertext_len, decryptedtext_len;
    unsigned char key[AES_KEYLEN];
    unsigned char iv[AES_GCM_IVLEN];
    unsigned char tag[AES_GCM_TAGLEN];

    // Lecture fichier
    read_file(input_filename, &plaintext, &plaintext_len);

    // Generate a random key and IV 
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

    // Allocation mémoire
    ciphertext = (unsigned char *)malloc(plaintext_len + AES_GCM_TAGLEN);
    if (ciphertext == NULL) {
        perror("Erreur mémoire");
        exit(1);
    }

    // Encryption
    ciphertext_len = aes_gcm_encrypt(plaintext, plaintext_len, NULL, 0, key, iv, AES_GCM_IVLEN, ciphertext, tag);

    // Ecriture du texte encrypté dans un fichier
    write_file(encrypted_filename, ciphertext, ciphertext_len);
    FILE *tag_file = fopen("tag.bin", "wb");
    if (tag_file == NULL) {
        perror("Erreur accès fichier");
        exit(1);
    }
    fwrite(tag, 1, AES_GCM_TAGLEN, tag_file);
    fclose(tag_file);

   
    decryptedtext = (unsigned char *)malloc(plaintext_len);
    if (decryptedtext == NULL) {
        perror("Erreur mémoire");
        exit(1);
    }

    // Decrypt the ciphertext
    decryptedtext_len = aes_gcm_decrypt(ciphertext, ciphertext_len, NULL, 0, tag, key, iv, AES_GCM_IVLEN, decryptedtext);
    if (decryptedtext_len < 0) {
        fprintf(stderr, "Tag validation failed, decryption unsuccessful.\n");
        exit(1);
    }

    // Ecriture du texte décrypté dans un fichier
    write_file(decrypted_filename, decryptedtext, decryptedtext_len);

    //On libère la mémoire
    free(plaintext);
    free(ciphertext);
    free(decryptedtext);

    return 0;
}