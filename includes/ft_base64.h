#ifndef FT_BASE64_H
#define FT_BASE64_H

#include <ft_openssl.h>

enum e_options_base64 {
    OPT_DECODE,
    OPT_ENCODE,
    OPT_INPUT_FILE,
    OPT_OUTPUT_FILE,
    OPT_NBR
};

struct s_options_base64 {
    enum e_base64_mode mode;
    const char *input_file;
    const char *output_file;
};

typedef struct s_options_base64 t_options_base64;
int parse_base64_args(unsigned int *nbr_arg, char **args,
                      t_options_base64 *options);

#endif