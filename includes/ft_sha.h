#ifndef SHA256_H
#define SHA256_H

#include <ft_md5.h>
#include <ft_openssl.h>

typedef t_options_md5 t_options_sha256;
typedef enum e_options_md5 e_options_sha256;
typedef t_options_md5 t_options_sha224;
typedef enum e_options_md5 e_options_sha224;
typedef t_options_md5 t_options_sha512;
typedef enum e_options_md5 e_options_sha512;

void hash_buff_sha256(const char *str, size_t len, u_int32_t digest[8]);
void hash_buff_sha512(const char *str, size_t len, u_int64_t digest[8]);

#endif