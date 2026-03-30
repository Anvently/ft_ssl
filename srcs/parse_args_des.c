#include <ft_des.h>

extern const char *executable_name;

static int register_base64(t_options_des *, char *);
static int register_encode(t_options_des *, char *);
static int register_decode(t_options_des *, char *);
static int register_input_file(t_options_des *, char *);
static int register_output_file(t_options_des *, char *);
static int register_key(t_options_des *, char *);
static int register_password_value(t_options_des *, char *);
static int register_salt(t_options_des *, char *);
static int register_iv(t_options_des *, char *);
static int register_md(t_options_des *, char *);
static int register_print_key(t_options_des *, char *);

static t_opt_flag options_list[OPT_NBR] = {
    [OPT_BASE64] = {.arg = ARG_NONE,
                    .short_id = 'a',
                    .long_id = "base64",
                    .handler = (int (*)(void *, char *))register_base64},
    [OPT_ENCODE] = {.arg = ARG_NONE,
                    .short_id = 'e',
                    .long_id = "encode",
                    .handler = (int (*)(void *, char *))register_encode},
    [OPT_DECODE] = {.arg = ARG_NONE,
                    .short_id = 'd',
                    .long_id = "decode",
                    .handler = (int (*)(void *, char *))register_decode},
    [OPT_INPUT_FILE] = {.arg = ARG_REQUIRED,
                        .short_id = 'i',
                        .long_id = "input",
                        .handler =
                            (int (*)(void *, char *))register_input_file},
    [OPT_OUTPUT_FILE] = {.arg = ARG_REQUIRED,
                         .short_id = 'o',
                         .long_id = "output",
                         .handler =
                             (int (*)(void *, char *))register_output_file},
    [OPT_KEY] = {.arg = ARG_REQUIRED,
                 .short_id = 'k',
                 .long_id = "key",
                 .handler = (int (*)(void *, char *))register_key},
    [OPT_PASSWORD_VALUE] = {.arg = ARG_REQUIRED,
                            .short_id = 'p',
                            .long_id = "pass",
                            .handler = (int (*)(
                                void *, char *))register_password_value},
    [OPT_SALT] = {.arg = ARG_REQUIRED,
                  .short_id = 's',
                  .long_id = "salt",
                  .handler = (int (*)(void *, char *))register_salt},
    [OPT_IV] = {.arg = ARG_REQUIRED,
                .short_id = 'v',
                .long_id = "iv",
                .handler = (int (*)(void *, char *))register_iv},
    [OPT_MD] = {.arg = ARG_REQUIRED,
                .short_id = 0,
                .long_id = "md",
                .handler = (int (*)(void *, char *))register_md},
    [OPT_PRINT_KEY] = {.arg = ARG_NONE,
                       .short_id = 'P',
                       .long_id = "print",
                       .handler = (int (*)(void *, char *))register_print_key}};

static int register_encode(t_options_des *opts, char *arg) {
    (void)arg;
    opts->mode = MODE_ENCODE;
    return (0);
}
static int register_decode(t_options_des *opts, char *arg) {
    (void)arg;
    opts->mode = MODE_DECODE;
    return (0);
}
static int register_input_file(t_options_des *opts, char *arg) {
    opts->input_file = arg;
    return (0);
}
static int register_output_file(t_options_des *opts, char *arg) {
    opts->output_file = arg;
    return (0);
}

static int register_base64(t_options_des *opts, char *arg) {
    (void)arg;
    opts->base64 = true;
    return (0);
}

u_int64_t padd_left_u64_hex(u_int64_t n) {
    for (u_int8_t i = 0; i < 16; i++) {
        if ((n & ((u_int64_t)0xF << ((15 - i) * 4))))
            return (n << (i * 4));
    }
    return (n);
}

static int register_key(t_options_des *opts, char *arg) {
    u_int64_t value;
    const char *ptr = arg;
    switch (ft_strtoul_hex(arg, &value, &ptr)) {
    default:
        break;
    case 1:
        ft_options_err("key", "overflow error");
        return (2);
    case 2:
        ft_options_err("key", "format error");
        return (2);
    }
    opts->key.value = padd_left_u64_hex(value);
    opts->key.given = true;
    return (0);
}

#define STRINGIFY(x) #x
// #define TOSTRING(x) STRINGIFY(x)
static int register_password_value(t_options_des *opts, char *arg) {
    if (ft_strlen(arg) > (MAX_PASSWORD_LEN - 1)) {
        ft_options_err("pass", "too big (max " STRINGIFY(MAX_PASSWORD_LEN) ")");
        return (2);
    }
    ft_strlcpy(opts->password.value, arg, MAX_PASSWORD_LEN);
    opts->password.prompt = false;
    return (0);
}
static int register_salt(t_options_des *opts, char *arg) {
    u_int64_t value;
    const char *ptr = arg;
    switch (ft_strtoul_hex(arg, &value, &ptr)) {
    default:
        break;
    case 1:
        ft_options_err("salt", "overflow error");
        return (2);
    case 2:
        ft_options_err("salt", "format error");
        return (2);
    }
    opts->salt.value = padd_left_u64_hex(value);
    opts->salt.given = true;
    return (0);
}
static int register_iv(t_options_des *opts, char *arg) {
    u_int64_t value;
    const char *ptr = arg;
    switch (ft_strtoul_hex(arg, &value, &ptr)) {
    default:
        break;
    case 1:
        ft_options_err("iv", "overflow error");
        return (2);
    case 2:
        ft_options_err("iv", "format error");
        return (2);
    }
    opts->iv.value = padd_left_u64_hex(value);
    opts->iv.given = true;
    return (0);
}
static int register_md(t_options_des *opts, char *arg) {
    opts->hash_option = arg;
    return (0);
}

static int register_print_key(t_options_des *opts, char *arg) {
    (void)arg;
    opts->print_key = true;
    return (0);
}

static void print_options(t_options_des *opts) __attribute_maybe_unused__;
static void print_options(t_options_des *opts) {
    ft_sdprintf(1, "salt=%lx\nkey=%lx\niv=%lx\n", opts->salt.value,
                opts->key.value, opts->iv.value);
    ft_sdprintf(1, "infile=%s\noutfile=%s\npass=%s\nmode=%d\n",
                opts->input_file, opts->output_file, opts->password.value,
                opts->mode);
}

static int read_pass(t_options_des *opts) {
    char *pass = NULL;

    pass = getpass("Password:");
    if (pass == NULL) {
        ft_sdprintf(1, "%s: des: %s\n", executable_name, strerror(errno));
        return (2);
    }
    if (ft_strlen(pass) > (MAX_PASSWORD_LEN - 1)) {
        ft_options_err("pass", "too big (max " STRINGIFY(MAX_PASSWORD_LEN) ")");
        return (2);
    }
    ft_strlcpy(opts->password.value, pass, MAX_PASSWORD_LEN);
    return (0);
}

int parse_des_args(unsigned int *nbr_arg, char **args, t_options_des *options) {
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
    if (options->key.given == false && options->password.prompt == true &&
        read_pass(options))
        return (2);
    // print_options(options);
    return (0);
}
