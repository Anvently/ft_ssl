#ifndef OPENSSL_H
#define OPENSSL_H
#include <errno.h>
#include <error.h>
#include <libft.h>
#include <string.h>
#include <unistd.h>

enum e_command {
    MD5,
    SHA256,
    SHA224,
    SHA512,
    BASE64,
    DES,
    DES_ECB,
    DES_CBC,
    DES_PCBC,
    DES_CFB,
    DES_OFB,
    DES3,
    DES3_ECB,
    DES3_CBC,
    DES3_PCBC,
    DES3_CFB,
    DES3_OFB,
    NBR_ALGORITHM
};

struct s_algorithm {
    const char *name;
    int (*func)(unsigned int, char **);
    enum { ALGO_TYPE_OTHER, ALGO_TYPE_DIGEST, ALGO_TYPE_CIPHER } type;
};

enum e_encryption_mode {
    ENC_MODE_ECB = 0,
    ENC_MODE_CBC,
    ENC_MODE_PCBC,
    ENC_MODE_CFB,
    ENC_MODE_OFB,
};

enum e_op_mode { OP_MODE_ENCODE, OP_MODE_DECODE };

int interactive_mode();
void print_commands();

int md5(unsigned int, char **);
int sha256(unsigned int, char **);
int sha224(unsigned int, char **);
int sha512(unsigned int, char **);
int base64(unsigned int nbr_arg, char **args);
int des_ecb(unsigned int nbr_arg, char **args);
int des_cbc(unsigned int nbr_arg, char **args);
int des_pcbc(unsigned int nbr_arg, char **args);
int des_cfb(unsigned int nbr_arg, char **args);
int des_ofb(unsigned int nbr_arg, char **args);
int des3_ecb(unsigned int nbr_arg, char **args);
int des3_cbc(unsigned int nbr_arg, char **args);
int des3_pcbc(unsigned int nbr_arg, char **args);
int des3_cfb(unsigned int nbr_arg, char **args);
int des3_ofb(unsigned int nbr_arg, char **args);

#endif