#include <ft_md5.h>

static const t_options_md5 default_opts = {
    .echo = false, .quiet = false, .reverse = false, .sums = NULL};
static const char *usage = "\
usage: ./openssl md5 [flags] [file/string]\n\
\n\
Flags:\n\
  -p, --echo            echo STDIN to STDOUT and append checksum to STDOUT.\n\
  -q, --quiet           quiet mode\n\
  -r, --reverse         reverse the format of the output\n\
  -s, --string=string   print the sum of the given string\n\
\n";

// static int
int parse_md5_args(unsigned int *nbr_arg, char **args, t_options_md5 *options);

static void free_opts(t_options_md5 *opts) {
    if (opts->sums) {
        ft_vector_free((t_vector **)&opts->sums);
    }
}

static void print_args(unsigned int nbr_arg, char **args,
                       t_options_md5 *options) {
    for (unsigned int i = 0; i < ft_vector_size(options->sums); i++) {
        printf("string: %s\n", options->sums[i]);
    }
    for (unsigned int i = 0; i < nbr_arg;) {
        if (args[i] == NULL) {
            args++;
            continue;
        }
        printf("file: %s\n", args[i]);
        i++;
    }
}

static int checksum_stdin(t_options_md5 *opts) { return (0); }

static int checksum_stdin(t_options_md5 *opts);
static int checksum_string(const char *str, t_options_md5 *opts);
static int checksum_file(const char *path, t_options_md5 *opts);

static const u_int8_t rotates[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
static const u_int32_t constants[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

void add_md5_block(u_int32_t state[4], const char block[128]) {
    u_int32_t new_state[4] = state;
    unsigned int f, g, tmp;

    for (unsigned int i = 0; i < 64; i++) {

        switch (i / 16) {
        case 0: // 0 to 15
            f = (new_state[1] & new_state[2]) | (~new_state[1] & new_state[3]);
            g = i;
            break;
        case 1: // 16 to 31
            f = (new_state[3] & new_state[1]) | (~new_state[3] & new_state[2]);
            g = (5 * i + 1) % 16;
            break;
        case 2: // 32 to 47
            f = new_state[1] ^ new_state[2] ^ new_state[3];
            g = (3 * i + 5) % 16;
            break;
        case 3: // 48 to 63
            f = new_state[2] ^ (new_state[1] | ~new_state[3]);
            g = (7 * i) % 16;
            break;
        }
        tmp = new_state[3];
        new_state[2] = new_state[1];
        new_state[1] = 1; // leftrotate((a + f + k[i] + w[g]), r[i]) + b
        new_state[0] = tmp;
    }
    state[0] += new_state[0];
    state[1] += new_state[1];
    state[2] += new_state[2];
    state[3] += new_state[3];
}

int md5(unsigned int nbr_arg, char **args) {
    t_options_md5 opts = default_opts;
    int ret = 0, func_ret;

    if (parse_md5_args(&nbr_arg, args, &opts))
        error(2, 0, "%s", usage);
    if (nbr_arg == 0) { // read stdin
        ret = checksum_stdin(&opts);
    } else { // read files
        for (unsigned int i = 0; i < nbr_arg;) {
            if (args[i] == NULL) {
                args++;
                continue;
            }
            func_ret = checksum_file(args[i], &opts);
            if (func_ret)
                i++;
        }
    }
    for (unsigned int i = 0; i < ft_vector_size(opts.sums); i++) {
        checksum_string(opts.sums[i], &opts);
    }
    free_opts(&opts);
    return (ret);
}