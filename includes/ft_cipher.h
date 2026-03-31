#ifndef FT_CIPHER_H
#define FT_CIPHER_H
#include <ft_openssl.h>

typedef u_int64_t (*t_fun_cipher)(u_int64_t block, void *data);

struct s_cipher_context {
    void *data;       // Algorithm dependant data
    const char *name; // algo name
    enum e_encryption_mode enc_mode;
    u_int64_t iv; // Stored in LE
    const char *payload;
    size_t remaining;
    size_t padlen;
    int fd_out;
    t_fun_cipher encrypt_fun;
    t_fun_cipher decrypt_fun;
};

int cipher_encrypt(struct s_cipher_context *ctx);
int cipher_decrypt(struct s_cipher_context *ctx);

#endif