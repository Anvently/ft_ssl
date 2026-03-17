#include <ft_sha256.h>

static const t_options_sha256 default_opts = {
    .echo = false, .quiet = false, .reverse = false, .sums = NULL};
static const char *usage = "\
usage: ./openssl sha256 [flags] [file/string]\n\
\n\
Flags:\n\
  -p, --echo            echo STDIN to STDOUT and append checksum to STDOUT.\n\
  -q, --quiet           quiet mode\n\
  -r, --reverse         reverse the format of the output\n\
  -s, --string=string   print the sum of the given string\n\
\n";

int parse_md5_args(unsigned int *nbr_arg, char **args, t_options_md5 *options);

static void free_opts(t_options_md5 *opts) {
    if (opts->sums) {
        ft_vector_free((t_vector **)&opts->sums);
    }
}

int sha256(unsigned int nbr_arg, char **args) {
    t_options_sha256 opts = default_opts;

    if (nbr_arg < 1)
        error(2, 0, "%s", usage);
    if (parse_md5_args(&nbr_arg, args, &opts))
        error(2, 0, "%s", usage);
    free_opts(&opts);
    return (0);
}