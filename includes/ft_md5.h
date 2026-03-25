#ifndef MD5_H
#define MD5_H

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <libft.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

enum e_options_md5 { OPT_ECHO, OPT_QUIET, OPT_REVERSE, OPT_SUM, OPT_NBR };
#define OPT_NBR OPT_NBR

struct s_options_md5 {
    bool echo;
    bool quiet;
    bool reverse;
    const char **sums; // vector of sum
};

typedef struct s_options_md5 t_options_md5;

void hash_buff_md5(const char *str, size_t len, u_int32_t digest[4]);

#endif