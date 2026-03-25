#ifndef FT_PBKDF_H
#define FT_PBKDF_H
#include <ft_openssl.h>

typedef void (*t_hash_func)(const char *payload, size_t payload_len,
                            void *output);

struct s_hash_props {
    const char *name;
    t_hash_func hash_func;
    size_t output_size;
};

struct s_pbkdf_arg {
    struct s_hash_props *hash_opts;
    size_t iteration; // c
    const char *password;
    size_t password_len; // P
    size_t dk_len;       // dkLen
    u_int64_t salt;
    void *key_out; // keyLen = dkLen / 2
    void *iv_out;  // ivLen = dkLen / 2
};

struct s_hash_props *get_hash_props(const char *name);

int pbkdf1(struct s_pbkdf_arg *args);

#endif