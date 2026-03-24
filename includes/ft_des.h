#ifndef FT_DES_H
#define FT_DES_H

#include <ft_openssl.h>

#define MAX_PASSWORD_LEN 128

enum e_options_des {
    OPT_BASE64,
    OPT_DECODE,
    OPT_ENCODE,
    OPT_INPUT_FILE,
    OPT_OUTPUT_FILE,
    OPT_KEY,
    OPT_PASSWORD, // Do nothing, password prompt is enabled by default
    OPT_PASSWORD_VALUE,
    OPT_SALT,
    OPT_IV, // == IV
    OPT_NBR
};

struct s_options_des {
    bool base64;
    enum { MODE_ENCODE, MODE_DECODE } mode;
    const char *input_file;
    const char *output_file;
    struct {
        char value[MAX_PASSWORD_LEN];
        bool prompt;
    } password;
    struct {
        u_int64_t value;
        bool given;
    } key;
    struct {
        u_int64_t value;
        bool given;
    } salt;
    struct {
        u_int64_t value;
        bool given;
    } iv;
};

typedef struct s_options_des t_options_des;
int parse_des_args(unsigned int *nbr_arg, char **args, t_options_des *options);

#endif