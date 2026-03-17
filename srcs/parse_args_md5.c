#include <ft_md5.h>

static int register_echo(t_options_md5 *, char *);
static int register_quiet(t_options_md5 *, char *);
static int register_reverse(t_options_md5 *, char *);
static int register_sum(t_options_md5 *, char *);

static t_opt_flag options_list[OPT_NBR] = {
    [OPT_ECHO] = {.arg = ARG_NONE,
                  .short_id = 'p',
                  .long_id = "echo",
                  .handler = (int (*)(void *, char *))register_echo},
    [OPT_QUIET] = {.arg = ARG_NONE,
                   .short_id = 'q',
                   .long_id = "quiet",
                   .handler = (int (*)(void *, char *))register_quiet},
    [OPT_REVERSE] = {.arg = ARG_NONE,
                     .short_id = 'r',
                     .long_id = "reverse",
                     .handler = (int (*)(void *, char *))register_reverse},
    [OPT_SUM] = {.arg = ARG_REQUIRED,
                 .short_id = 's',
                 .long_id = "sum",
                 .handler = (int (*)(void *, char *))register_sum},
};

static int register_echo(t_options_md5 *opts, char *arg) {
    (void)arg;
    opts->echo = true;
    return (0);
}
static int register_quiet(t_options_md5 *opts, char *arg) {
    (void)arg;
    opts->quiet = true;
    return (0);
}
static int register_reverse(t_options_md5 *opts, char *arg) {
    (void)arg;
    opts->reverse = true;
    return (0);
}
static int register_sum(t_options_md5 *opts, char *arg) {
    if (opts->sums == NULL) {
        opts->sums = ft_vector_create(sizeof(const char *), 2);
        if (opts->sums == NULL)
            error(-1, errno, "allocating vector of strings");
    }
    if (ft_vector_push((t_vector **)&opts->sums, &arg))
        error(-1, errno, "reallocating vector of strings");
    return (0);
}

int parse_md5_args(unsigned int *nbr_arg, char **args, t_options_md5 *options) {
    struct s_options_parser_args parser_arg = {.args = args,
                                               .nbr_argument = *nbr_arg,
                                               .options_map = &options_list[0],
                                               .options_map_len = OPT_NBR};
    if (ft_options_retrieve(&parser_arg, (void *)options))
        return (2);
    *nbr_arg = parser_arg.nbr_argument;
    return (0);
}