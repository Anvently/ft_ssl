#include <errno.h>
#include <error.h>
#include <libft.h>
#include <string.h>
#include <unistd.h>

enum e_options { OPT_ECHO, OPT_QUIET, OPT_REVERSE, OPT_SUM, OPT_NBR };

#define OPT_NBR OPT_NBR

struct s_options {
    bool echo;
    bool quiet;
    bool reverse;
    const char *sum;
};