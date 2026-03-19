#include <ft_openssl.h>

static const char *usage = "\
usage: ./openssl command [...]\n\
\n\
Commands: md5, sha256\n";

const char *executable_name = "ft_ssl";

const struct s_algorithm algorithms[NBR_ALGORITHM] = {
    [MD5] = {.func = md5, .name = "md5"},
    [SHA256] = {.func = sha256, .name = "sha256"}};

int main(int argc, char **argv) {

    if (argc < 2)
        return (interactive_mode());
    for (unsigned int i = 0; i < NBR_ALGORITHM; i++) {
        if (ft_strcmp(algorithms[i].name, argv[1]) == 0)
            return (algorithms[i].func((unsigned int)(argc - 2), argv + 2));
    }
    error(2, 0, "%s", usage);
}