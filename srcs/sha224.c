#include <ft_openssl_utils.h>
#include <ft_sha.h>

static const t_options_sha224 default_opts = {
    .echo = false, .quiet = false, .reverse = false, .sums = NULL};
static const char *usage = "\
usage: ./openssl sha224 [flags] [file/string]\n\
\n\
Flags:\n\
  -p, --echo            echo STDIN to STDOUT and append checksum to STDOUT.\n\
  -q, --quiet           quiet mode\n\
  -r, --reverse         reverse the format of the output\n\
  -s, --string=string   print the sum of the given string\n\
\n";

extern const char *executable_name;

int parse_md5_args(unsigned int *nbr_arg, char **args, t_options_md5 *options);

static int parse_sha224_args(unsigned int *nbr_arg, char **args,
                             t_options_sha224 *options) {
    return (parse_md5_args(nbr_arg, args, options));
}

static void free_opts(t_options_sha224 *opts) {
    if (opts->sums) {
        ft_vector_free((t_vector **)&opts->sums);
    }
}

static u_int32_t init_state[8] = {0xc1059ed8, 0x367cd507, 0x3070dd17,
                                  0xf70e5939, 0xffc00b31, 0x68581511,
                                  0x64f98fa7, 0xbefa4fa4};

static const u_int32_t constants[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static void add_sha224_block(u_int32_t state[8], const char block[64]) {
    u_int32_t new_state[8] = {state[0], state[1], state[2], state[3],
                              state[4], state[5], state[6], state[7]};
    u_int32_t w[64] = {0};
    u_int32_t s0, s1, tmp1, tmp2;

    for (int i = 0; i < 16; i++) { // Copy first 16 words to w
        w[i] = REVERT_ENDIANESS_32(((u_int32_t *)block)[i]);
    }
    for (unsigned int i = 16; i < 64; i++) { // Compute remaining  48 words of w
        s0 = right_rotate(w[i - 15], 7) ^ right_rotate(w[i - 15], 18) ^
             (w[i - 15] >> 3);
        s1 = right_rotate(w[i - 2], 17) ^ right_rotate(w[i - 2], 19) ^
             (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    for (unsigned int i = 0; i < 64; i++) {
        s0 = right_rotate(new_state[4], 6) ^ right_rotate(new_state[4], 11) ^
             right_rotate(new_state[4], 25);
        s1 = (new_state[4] & new_state[5]) ^ (~(new_state[4]) & new_state[6]);
        tmp1 = new_state[7] + s0 + s1 + constants[i] + w[i];
        s0 = right_rotate(new_state[0], 2) ^ right_rotate(new_state[0], 13) ^
             right_rotate(new_state[0], 22);
        s1 = (new_state[0] & new_state[1]) ^ (new_state[0] & new_state[2]) ^
             (new_state[1] & new_state[2]);
        tmp2 = s0 + s1;

        new_state[7] = new_state[6];
        new_state[6] = new_state[5];
        new_state[5] = new_state[4];
        new_state[4] = new_state[3] + tmp1;
        new_state[3] = new_state[2];
        new_state[2] = new_state[1];
        new_state[1] = new_state[0];
        new_state[0] = tmp1 + tmp2;
    }
    state[0] += new_state[0];
    state[1] += new_state[1];
    state[2] += new_state[2];
    state[3] += new_state[3];
    state[4] += new_state[4];
    state[5] += new_state[5];
    state[6] += new_state[6];
    state[7] += new_state[7];
}

static void hash_buff(const char *str, size_t len, u_int32_t digest[8]) {
    size_t remaining = len;
    char padding[128] = {0};
    ft_memcpy(digest, init_state, sizeof(init_state));
    while (remaining >= 64) {
        add_sha224_block(digest, str);
        remaining -= 64;
        str += 64;
    }
    ft_memcpy(padding, str, remaining);
    // add 1 bits after message (message is always % of 8 bits)
    padding[remaining] = 128; // 0b10000000
    if (64 - remaining <= 8) {
        // Case where the minimum padding does not fit in a single block
        for (int i = 0; i < 8; i++)
            padding[120 + i] = ((len * 8) >> (56 - i * 8)) & 0xFF;
        add_sha224_block(digest, padding);
        add_sha224_block(digest, padding + 64);
    } else {
        for (int i = 0; i < 8; i++)
            padding[56 + i] = ((len * 8) >> (56 - i * 8)) & 0xFF;
        add_sha224_block(digest, padding);
    }
}

static void print_hash(u_int32_t digest[8], const char *name, bool quote,
                       t_options_sha224 *opts) {
    if (name == NULL)
        ft_sdprintf(1, "%x%x%x%x%x%x%x", digest[0], digest[1], digest[2],
                    digest[3], digest[4], digest[5], digest[6]);
    else if (opts->quiet == true)
        ft_sdprintf(1, "%x%x%x%x%x%x%x\n", digest[0], digest[1], digest[2],
                    digest[3], digest[4], digest[5], digest[6]);
    else if (opts->reverse == false)
        ft_sdprintf(1, "SHA224(%c%s%c)= %x%x%x%x%x%x%x\n", quote ? '"' : 0,
                    name, quote ? '"' : 0, digest[0], digest[1], digest[2],
                    digest[3], digest[4], digest[5], digest[6]);
    else
        ft_sdprintf(1, "%x%x%x%x%x%x%x %c%s%c\n", digest[0], digest[1],
                    digest[2], digest[3], digest[4], digest[5], digest[6],
                    quote ? '"' : 0, name, quote ? '"' : 0);
}

static void sha224_string(const char *str, t_options_sha224 *opts) {
    u_int32_t digest[8];

    hash_buff(str, ft_strlen(str), digest);
    print_hash(digest, str, true, opts);
}

static int sha224_file(const char *path, t_options_sha224 *opts) {
    u_int32_t digest[8];
    char *vec;
    int fd = -1;

    fd = open(path, O_RDONLY, 0);
    if (fd < 0 || read_file(fd, &vec)) {
        ft_sdprintf(1, "%s: sha224: %s: %s\n", executable_name, path,
                    strerror(errno));
        if (fd >= 0)
            close(fd);
        return (1);
    }
    close(fd);
    hash_buff(vec, ft_vector_size(vec) - 1, digest);
    print_hash(digest, path, false, opts);
    ft_vector_free((t_vector **)&vec);
    return (0);
}

static int sha224_stdin(t_options_sha224 *opts) {
    u_int32_t digest[8];
    char *vec = NULL;

    if (read_file(0, &vec)) {
        ft_vector_free((t_vector **)&vec);
        ft_sdprintf(1, "%s: sha256: stdin: %s\n", executable_name,
                    strerror(errno));
        return (1);
    }
    // ft_hexdump(vec, ft_vector_size(vec) - 1, 1, 0);
    hash_buff(vec, ft_vector_size(vec) - 1, digest);
    print_hash(digest, opts->echo ? vec : "stdin", opts->echo ? true : false,
               opts);
    ft_vector_free((t_vector **)&vec);
    return (0);
}

int sha224(unsigned int nbr_arg, char **args) {
    t_options_sha224 opts = default_opts;
    int ret = 0, func_ret;

    if (parse_sha224_args(&nbr_arg, args, &opts))
        error(2, 0, "%s", usage);
    if ((nbr_arg == 0 && ft_vector_size(opts.sums) == 0) ||
        opts.echo) { // read stdin
        ret = sha224_stdin(&opts);
    }

    for (unsigned int i = 0; i < nbr_arg;) { // read files
        if (args[i] == NULL) {
            args++;
            continue;
        }
        func_ret = sha224_file(args[i], &opts);
        if (func_ret)
            ret++;
        i++;
    }

    for (unsigned int i = 0; i < ft_vector_size(opts.sums); i++) {
        sha224_string(opts.sums[i], &opts);
    }
    free_opts(&opts);
    return (ret);
}