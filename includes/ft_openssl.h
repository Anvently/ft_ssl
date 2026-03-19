#ifndef OPENSSL_H
#define OPENSSL_H
#include <errno.h>
#include <error.h>
#include <libft.h>
#include <string.h>
#include <unistd.h>

enum e_command { MD5, SHA256, NBR_ALGORITHM };

struct s_algorithm {
    const char *name;
    int (*func)(unsigned int, char **);
};

int interactive_mode();

int md5(unsigned int, char **);
int sha256(unsigned int, char **);

#endif