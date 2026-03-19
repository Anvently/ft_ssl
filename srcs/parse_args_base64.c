#include <ft_base64.h>

static int register_encode(t_options_base64 *, char *);
static int register_decode(t_options_base64 *, char *);
static int register_input_file(t_options_base64 *, char *);
static int register_output_file(t_options_base64 *, char *);

static t_opt_flag options_list[OPT_NBR] = {
    [OPT_ENCODE] = {.arg = ARG_NONE,
                    .short_id = 'e',
                    .long_id = "encode",
                    .handler = (int (*)(void *, char *))register_encode},
    [OPT_DECODE] = {.arg = ARG_NONE,
                    .short_id = 'd',
                    .long_id = "decode",
                    .handler = (int (*)(void *, char *))register_decode},
    [OPT_INPUT_FILE] = {.arg = ARG_NONE,
                        .short_id = 'i',
                        .long_id = "input",
                        .handler =
                            (int (*)(void *, char *))register_input_file},
    [OPT_OUTPUT_FILE] = {.arg = ARG_REQUIRED,
                         .short_id = 'o',
                         .long_id = "output",
                         .handler =
                             (int (*)(void *, char *))register_output_file},
};

static int register_encode(t_options_base64 *opts, char *arg) {
    (void)arg;
    opts->mode = MODE_ENCODE;
    return (0);
}
static int register_decode(t_options_base64 *opts, char *arg) {
    (void)arg;
    opts->mode = MODE_DECODE;
    return (0);
}
static int register_input_file(t_options_base64 *opts, char *arg) {
    opts->input_file = arg;
    return (0);
}
static int register_output_file(t_options_base64 *opts, char *arg) {
    opts->output_file = arg;
    return (0);
}

int parse_base64_args(unsigned int *nbr_arg, char **args,
                      t_options_base64 *options) {
    struct s_options_parser_args parser_arg = {.args = args,
                                               .nbr_argument = *nbr_arg,
                                               .options_map = &options_list[0],
                                               .options_map_len = OPT_NBR};
    if (ft_options_retrieve(&parser_arg, (void *)options))
        return (2);
    *nbr_arg = parser_arg.nbr_argument;
    if (*nbr_arg > 0) {
        ft_sdprintf(2, "Invalid number of arguments.\n");
        return (2);
    }
    return (0);
}