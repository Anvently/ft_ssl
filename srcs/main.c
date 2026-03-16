#include <openssl.h>

static const t_options default_opts = {
    .echo = false, .quiet = false, .reverse = false, .sum = NULL};
static const char *usage = "\
usage: ./openssl command [flags] [file/string]\n\
\n\
  -p, --echo            echo STDIN to STDOUT and append checksum to STDOUT.\n\
  -q, --quiet           quiet mode\n\
  -r, --reverse         reverse the format of the output\n\
  -s, --string=string   print the sum of the given string\n\
\n";
const char *executable_name = "ft_openssl";

int main(int argc, char **argv) {
    unsigned int nbr_arg;
    t_options opts = default_opts;

    if (argc < 3)
        error(2, 0, "%s", usage);
    if (ft_options_retrieve(argc - 1, argv + 1, &opts, &nbr_arg))
        error(2, 0, "%s", usage);
    (void)nbr_arg;
    (void)default_opts;
    return (0);
}