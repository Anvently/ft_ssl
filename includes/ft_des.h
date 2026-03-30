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
    OPT_PASSWORD_VALUE,
    OPT_SALT,
    OPT_IV,        // == IV
    OPT_MD,        // Hash algorithm use to perform pbkdf
    OPT_PRINT_KEY, // Print encryption key, salt and IV
    OPT_NBR
};

enum e_encryption_mode { ENC_MODE_ECB = 0, ENC_MODE_CBC = 1 };

struct s_options_des {
    bool base64;
    enum e_op_mode { MODE_ENCODE, MODE_DECODE } mode;
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
    const char *hash_option;
    enum e_encryption_mode enc_mode;
    bool print_key;
};

typedef struct s_options_des t_options_des;
int parse_des_args(unsigned int *nbr_arg, char **args, t_options_des *options);

#endif