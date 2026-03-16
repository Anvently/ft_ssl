#include <openssl.h>

static int register_echo(t_options *, char *);
static int register_quiet(t_options *, char *);
static int register_reverse(t_options *, char *);
static int register_sum(t_options *, char *);

int NBR_OPTIONS = OPT_NBR;

t_opt_flag options_list[OPT_NBR] = {
    [OPT_ECHO] = {.arg = ARG_NONE,
                  .short_id = 'p',
                  .long_id = "echo",
                  .handler = register_echo},
    [OPT_QUIET] = {.arg = ARG_NONE,
                   .short_id = 'q',
                   .long_id = "quiet",
                   .handler = register_quiet},
    [OPT_REVERSE] = {.arg = ARG_NONE,
                     .short_id = 'r',
                     .long_id = "reverse",
                     .handler = register_reverse},
    [OPT_SUM] = {.arg = ARG_REQUIRED,
                 .short_id = 's',
                 .long_id = "sum",
                 .handler = register_sum},
};
t_opt_flag *options_map = &options_list[0];

static int register_echo(t_options *opts, char *arg) {
    (void)arg;
    opts->echo = true;
    return (0);
}
static int register_quiet(t_options *opts, char *arg) {
    (void)arg;
    opts->quiet = true;
    return (0);
}
static int register_reverse(t_options *opts, char *arg) {
    (void)arg;
    opts->reverse = true;
    return (0);
}
static int register_sum(t_options *opts, char *arg) {
    opts->sum = arg;
    return (0);
}
