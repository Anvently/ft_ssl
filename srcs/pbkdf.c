#include <ft_md5.h>
#include <ft_openssl_utils.h>
#include <ft_pbkdf.h>
#include <ft_sha.h>

// clang-format off
/*

https://crypto.stackexchange.com/questions/3298/is-there-a-standard-for-openssl-interoperable-aes-encryption/35614#35614
https://security.stackexchange.com/questions/29106/openssl-recover-key-and-iv-by-passphrase

c         = iteration count
DK        = derived key
dkLen     = derived key length in octet 
l         = len in block of derived key
IV        = initialization vector
K         = encryption key
Hash      = underlying hash function
PRF       = underlying pseudorandom function
hLen      = length in octet of pseudorandom function output (PRF)
KDF       = key derivation function 
P         = password
S         = salt
PS        = padding string
psLen     = length in octet of padding string

DK = KDF (P, S)


TO derive key in decryption, we need to know :
- S
- c
- Hash 

dkLen = 8
S = PRF(dkLen)
c = 1000
P = input



ADD SALT TO PASSWORD

FOR X ITERATION:
    HASH COMBINATION WITH ANY HASH FUNCTION

*/
// clang-format on

static struct s_hash_props hash_options[] = {
    [0] = {.name = "md5",
           .hash_func = (t_hash_func)hash_buff_md5_be,
           .output_size = 16},
    [1] = {.name = "sha256",
           .hash_func = (t_hash_func)hash_buff_sha256_be,
           .output_size = 32},
    [2] = {.name = "sha512",
           .hash_func = (t_hash_func)hash_buff_sha512_be,
           .output_size = 64},
};

struct s_hash_props *get_hash_props(const char *name) {
    for (unsigned int i = 0;
         i < (sizeof(hash_options) / sizeof(struct s_hash_props)); i++) {
        if (ft_strcmp(name, hash_options[i].name) == 0)
            return (&hash_options[i]);
    }
    return (NULL);
}

int pbkdf1(struct s_pbkdf_arg *args);

/// @brief Implementation of PBKDF algorithm. DK is returned in canonical (big
/// endian) form.
/// @param args
/// @return ```0``` for success, ```1``` if input error. Exit on allocation
/// error
int pbkdf1(struct s_pbkdf_arg *args) {
    char *data;
    char *digest; // We may just use data as inpout/output buffer, but if the
                  // hash algorithm proceed in 2 block and write bigger digest
                  // than original block size (unlikely?), it will break
    size_t data_size;
    struct s_hash_props *hash_props = args->hash_opts;

    if (args->dk_len > hash_props->output_size || args->iteration == 0)
        return (1);
    // Concatenate password with salt
    data_size = args->password_len + sizeof(args->salt);
    data = malloc(data_size);
    digest = malloc(hash_props->output_size);
    if (data == NULL || digest == NULL)
        error(-1, errno, "allocating data for password and salt concatenation");
    ft_memcpy(data, args->password, args->password_len);
    ft_memcpy(data + args->password_len, &args->salt, sizeof(args->salt));
    ft_hexdump(data, data_size, 1, 0);
    hash_props->hash_func(data, data_size, digest);
    data_size = hash_props->output_size;
    for (size_t i = 1; i < args->iteration; i++) {
        ft_memcpy(data, digest, hash_props->output_size);
        hash_props->hash_func(data, data_size, digest);
    }
    ft_hexdump(digest, hash_props->output_size, 1, 0);
    ft_memcpy(args->dk_out, digest, args->dk_len);
    free(data);
    free(digest);
    return (0);
}