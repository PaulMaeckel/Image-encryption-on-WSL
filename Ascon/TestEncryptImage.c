#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ascon.h"
#include "ascon_aead128.c"
#include "ascon_internal.h"
#include "ascon_permutations.c"
#include "ascon_buffering.c"
#include "ascon_aead_common.c"

int main() {
    FILE *file = fopen("blue.tiff", "rb"); // rb pour ouvrir l'image en mode binaire
    if (file == NULL) {
        perror("Erreur accès image");
        return 1;
    }

    // Lire le contenu du fichier image
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *bufferimage = (unsigned char *)malloc(file_size); //allocation pour preparer l'espace memoire
    if (bufferimage == NULL) {
        perror("Erreur memoire");
        fclose(file);
        return 1;
    }

    fread(bufferimage, 1, file_size, file); //Le contenu de bufferimage est en binaire, inutile d'essayer de le print.
    fclose(file);

    const uint8_t secret_key[ASCON_AEAD128_KEY_LEN] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6
    };
    const uint8_t unique_nonce[ASCON_AEAD_NONCE_LEN] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6
    }; //16*8 = 128
    ascon_aead_ctx_t ctx;
    ascon_aead128_init(&ctx, secret_key, unique_nonce);

    // Now we feed any associated data into the cipher first
    // Our data is fragmented into 2 parts, so we feed one at the time.
    const char associated_data_pt1[] = "2 messages will foll";
    const char associated_data_pt2[] = "ow, but they are both secret.";

    ascon_aead128_assoc_data_update(&ctx, (uint8_t*) associated_data_pt1, strlen(associated_data_pt1));
    ascon_aead128_assoc_data_update(&ctx, (uint8_t*) associated_data_pt2, strlen(associated_data_pt2));

    // Chiffrement des données binaires de l'image
    uint8_t *ciphertext = (uint8_t *)malloc(file_size + ASCON_AEAD_TAG_MIN_SECURE_LEN);
    if (ciphertext == NULL) {
        perror("Memory error");
        free(bufferimage);
        return 1;
    }

    size_t ciphertext_len = ascon_aead128_encrypt_update(&ctx, ciphertext, bufferimage, file_size);

    // Etape finale de l'encryption
    uint8_t tag[ASCON_AEAD_TAG_MIN_SECURE_LEN];
    ciphertext_len += ascon_aead128_encrypt_final(&ctx, ciphertext + ciphertext_len, tag, sizeof(tag));

    // Sauvegarder les données chiffrées dans un fichier
    FILE *enc_file = fopen("encrypted_image.bin", "wb");
    if (enc_file == NULL) {
        perror("Error opening file");
        free(ciphertext);
        free(bufferimage);
        return 1;
    }

    fwrite(ciphertext, 1, ciphertext_len, enc_file);
    fwrite(tag, 1, sizeof(tag), enc_file);
    fclose(enc_file);

    free(ciphertext);

    // Now we can decrypt, reusing the same key, nonce and associated data
    ascon_aead128_init(&ctx, secret_key, unique_nonce);
    ascon_aead128_assoc_data_update(&ctx, (uint8_t*) associated_data_pt1, strlen(associated_data_pt1));
    ascon_aead128_assoc_data_update(&ctx, (uint8_t*) associated_data_pt2, strlen(associated_data_pt2));

    // Lire les données chiffrées
    enc_file = fopen("encrypted_image.bin", "rb");
    if (enc_file == NULL) {
        perror("Error opening file");
        free(bufferimage);
        return 1;
    }

    fseek(enc_file, 0, SEEK_END);
    long enc_file_size = ftell(enc_file);
    fseek(enc_file, 0, SEEK_SET);

    uint8_t *enc_buffer = (uint8_t *)malloc(enc_file_size);
    if (enc_buffer == NULL) {
        perror("Memory error");
        fclose(enc_file);
        free(bufferimage);
        return 1;
    }

    fread(enc_buffer, 1, enc_file_size, enc_file);
    fclose(enc_file);

    uint8_t *decrypted = (uint8_t *)malloc(file_size);
    if (decrypted == NULL) {
        perror("Memory error");
        free(enc_buffer);
        free(bufferimage);
        return 1;
    }

    size_t decrypted_len = ascon_aead128_decrypt_update(&ctx, decrypted, enc_buffer, enc_file_size - ASCON_AEAD_TAG_MIN_SECURE_LEN);    

    // The final decryption step automatically checks the tag
    bool is_tag_valid = false;
    ascon_aead128_decrypt_final(&ctx, decrypted + decrypted_len, &is_tag_valid, enc_buffer + enc_file_size - ASCON_AEAD_TAG_MIN_SECURE_LEN, ASCON_AEAD_TAG_MIN_SECURE_LEN);

    if (!is_tag_valid) {
        fprintf(stderr, "Tag validation failed!\n");
        free(decrypted);
        free(enc_buffer);
        free(bufferimage);
        return 1;
    }

    // Sauvegarder l'image déchiffrée dans un fichier
    FILE *out_file = fopen("decrypted_image.tiff", "wb");
    if (out_file == NULL) {
        perror("Error opening file");
        free(decrypted);
        free(enc_buffer);
        free(bufferimage);
        return 1;
    }

    fwrite(decrypted, 1, file_size, out_file);
    fclose(out_file);

    free(bufferimage);
    free(decrypted);
    free(enc_buffer);

    return 0;
}