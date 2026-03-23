#ifndef OPENSSL_H
#define OPENSSL_H
#include <errno.h>
#include <error.h>
#include <libft.h>
#include <string.h>
#include <unistd.h>

enum e_command { MD5, SHA256, SHA224, SHA512, BASE64, NBR_ALGORITHM };

struct s_algorithm {
    const char *name;
    int (*func)(unsigned int, char **);
};

int interactive_mode();
void print_commands();

int md5(unsigned int, char **);
int sha256(unsigned int, char **);
int sha224(unsigned int, char **);
int sha512(unsigned int, char **);
int base64(unsigned int nbr_arg, char **args);

#endif