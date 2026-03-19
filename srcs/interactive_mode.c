
#include <ft_openssl.h>

extern const struct s_algorithm algorithms[NBR_ALGORITHM];

static const char *usage = "\
Commands: md5, sha256, sha224, sha512\n";

static int handle_command(int argc, char **argv) {
    if (argc == 0)
        return (0);
    for (unsigned int i = 0; i < NBR_ALGORITHM; i++) {
        if (ft_strcmp(algorithms[i].name, argv[0]) == 0)
            return (algorithms[i].func((unsigned int)(argc - 1), argv + 1));
    }
    ft_sdprintf(1, "%s", usage);
    return (1);
}

static int cmp_fun(char c) { return (ft_isspace(c)); }

int interactive_mode() {
    ssize_t nread;
    char line[1024];
    char **argv = NULL;
    size_t argc;

    do {
        ft_sdprintf(1, ">");
        nread = read(0, line, sizeof(line) - 1);
        if (nread < 0)
            error(1, errno, "reading line input in interactive mode");
        else if (nread == 0)
            break;
        line[nread] = '\0';
        argv = ft_split_static(line, cmp_fun);
        if (argv == NULL)
            error(1, errno, "parsing line input in interactive mode");
        argc = ft_strslen(argv);
        handle_command(argc, argv);
        free(argv);
    } while (nread > 0);
    return (0);
}
