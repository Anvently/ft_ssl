#include <ft_openssl.h>

static const char *usage = "\
usage: ./openssl command [...]\n\
\n";

const char *executable_name = "ft_ssl";

const struct s_algorithm algorithms[NBR_ALGORITHM] = {
    [MD5] = {.func = md5, .name = "md5"},
    [SHA256] = {.func = sha256, .name = "sha256"},
    [SHA224] = {.func = sha224, .name = "sha224"},
    [SHA512] = {.func = sha512, .name = "sha512"},
    [BASE64] = {.func = base64, .name = "base64"}};

void print_commands() {
    ft_sdprintf(1, "Commands: ");
    for (unsigned int i = 0; i < NBR_ALGORITHM; i++) {
        ft_sdprintf(1, "%s%s", i == 0 ? "" : ", ", algorithms[i].name);
    }
    ft_sdprintf(1, "\n");
}

void error_usage() {
    ft_sdprintf(1, "%s", usage);
    print_commands();
    exit(2);
}

int main(int argc, char **argv) {

    if (argc < 2)
        return (interactive_mode());
    for (unsigned int i = 0; i < NBR_ALGORITHM; i++) {
        if (ft_strcmp(algorithms[i].name, argv[1]) == 0)
            return (algorithms[i].func((unsigned int)(argc - 2), argv + 2));
    }
    error_usage();
}