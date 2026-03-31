#include <ft_openssl_utils.h>
#include <ft_sha.h>

static const t_options_sha512 default_opts = {
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

extern const char *executable_name;

int parse_md5_args(unsigned int *nbr_arg, char **args, t_options_md5 *options);

static int parse_sha_args(unsigned int *nbr_arg, char **args,
                          t_options_sha512 *options) {
    return (parse_md5_args(nbr_arg, args, options));
}

static void free_opts(t_options_sha512 *opts) {
    if (opts->sums) {
        ft_vector_free((t_vector **)&opts->sums);
    }
}

static u_int64_t init_state_512[8] = {0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
                                      0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                                      0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                                      0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};

static const u_int64_t constants[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
    0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
    0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
    0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
    0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
    0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
    0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
    0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
    0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

static void add_sha512_block(u_int64_t state[8], const char block[128]) {
    u_int64_t new_state[8] = {state[0], state[1], state[2], state[3],
                              state[4], state[5], state[6], state[7]};
    u_int64_t w[80] = {0};
    u_int64_t s0, s1, tmp1, tmp2;

    for (int i = 0; i < 16; i++) { // Copy first 16 words to w
        w[i] = REVERT_ENDIANESS_64(((u_int64_t *)block)[i]);
    }
    for (unsigned int i = 16; i < 80; i++) { // Compute remaining  48 words of w
        s0 = right_rotate64(w[i - 15], 1) ^ right_rotate64(w[i - 15], 8) ^
             (w[i - 15] >> 7);
        s1 = right_rotate64(w[i - 2], 19) ^ right_rotate64(w[i - 2], 61) ^
             (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    for (unsigned int i = 0; i < 80; i++) {
        s0 = right_rotate64(new_state[4], 14) ^
             right_rotate64(new_state[4], 18) ^
             right_rotate64(new_state[4], 41);
        s1 = (new_state[4] & new_state[5]) ^ (~(new_state[4]) & new_state[6]);
        tmp1 = new_state[7] + s0 + s1 + constants[i] + w[i];
        s0 = right_rotate64(new_state[0], 28) ^
             right_rotate64(new_state[0], 34) ^
             right_rotate64(new_state[0], 39);
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

void hash_buff_sha512_be(const char *str, size_t len, void *digest) {
    hash_buff_sha512(str, len, (u_int64_t *)digest);
    for (unsigned int i = 0; i < 8; i++) {
        ((u_int64_t *)digest)[i] = htobe64(((u_int64_t *)digest)[i]);
    }
}

void hash_buff_sha512(const char *str, size_t len, u_int64_t digest[8]) {
    size_t remaining = len;
    char padding[256] = {0};
    ft_memcpy(digest, init_state_512, sizeof(init_state_512));
    while (remaining >= 128) {
        add_sha512_block(digest, str);
        remaining -= 128;
        str += 128;
    }
    ft_memcpy(padding, str, remaining);
    // add 1 bits after message (message is always % of 8 bits)
    padding[remaining] = 128; // 0b10000000
    if (128 - remaining <= 16) {
        // Case where the minimum padding does not fit in a single block
        bzero(padding + 240, 8);
        for (int i = 0; i < 8; i++)
            padding[248 + i] = (((u_int64_t)len * 8) >> (56 - i * 8)) & 0xFF;
        add_sha512_block(digest, padding);
        add_sha512_block(digest, padding + 128);
    } else {
        bzero(padding + 112, 8);
        for (int i = 0; i < 8; i++)
            padding[120 + i] = (((u_int64_t)len * 8) >> (56 - i * 8)) & 0xFF;
        add_sha512_block(digest, padding);
    }
}

static void print_hash(u_int64_t digest[8], const char *name, bool quote,
                       t_options_sha512 *opts) {
    if (name == NULL)
        ft_sdprintf(1, "%lx%lx%lx%lx%lx%lx%lx%lx", digest[0], digest[1],
                    digest[2], digest[3], digest[4], digest[5], digest[6],
                    digest[7]);
    else if (opts->quiet == true)
        ft_sdprintf(1, "%lx%lx%lx%lx%lx%lx%lx%lx\n", digest[0], digest[1],
                    digest[2], digest[3], digest[4], digest[5], digest[6],
                    digest[7]);
    else if (opts->reverse == false)
        ft_sdprintf(1, "SHA512(%c%s%c)= %lx%lx%lx%lx%lx%lx%lx%lx\n",
                    quote ? '"' : 0, name, quote ? '"' : 0, digest[0],
                    digest[1], digest[2], digest[3], digest[4], digest[5],
                    digest[6], digest[7]);
    else
        ft_sdprintf(1, "%lx%lx%lx%lx%lx%lx%lx%lx %c%s%c\n", digest[0],
                    digest[1], digest[2], digest[3], digest[4], digest[5],
                    digest[6], digest[7], quote ? '"' : 0, name,
                    quote ? '"' : 0);
}

static void sha224_string(const char *str, t_options_sha512 *opts) {
    u_int64_t digest[8];

    hash_buff_sha512(str, ft_strlen(str), digest);
    print_hash(digest, str, true, opts);
}

static int sha512_file(const char *path, t_options_sha512 *opts) {
    u_int64_t digest[8];
    char *vec;
    int fd = -1;

    fd = open(path, O_RDONLY, 0);
    if (fd < 0 || read_file(fd, &vec)) {
        ft_sdprintf(2, "%s: sha512: %s: %s\n", executable_name, path,
                    strerror(errno));
        if (fd >= 0)
            close(fd);
        return (1);
    }
    close(fd);
    hash_buff_sha512(vec, ft_vector_size(vec) - 1, digest);
    print_hash(digest, path, false, opts);
    ft_vector_free((t_vector **)&vec);
    return (0);
}

static int sha512_stdin(t_options_sha512 *opts) {
    u_int64_t digest[8];
    char *vec = NULL;

    if (read_file(0, &vec)) {
        ft_vector_free((t_vector **)&vec);
        ft_sdprintf(2, "%s: sha512: stdin: %s\n", executable_name,
                    strerror(errno));
        return (1);
    }
    // ft_hexdump(vec, ft_vector_size(vec) - 1, 1, 0);
    hash_buff_sha512(vec, ft_vector_size(vec) - 1, digest);
    print_hash(digest, opts->echo ? vec : "stdin", opts->echo ? true : false,
               opts);
    ft_vector_free((t_vector **)&vec);
    return (0);
}

int sha512(unsigned int nbr_arg, char **args) {
    t_options_sha512 opts = default_opts;
    int ret = 0, func_ret;

    if (parse_sha_args(&nbr_arg, args, &opts))
        error(2, 0, "%s", usage);
    if ((nbr_arg == 0 && ft_vector_size(opts.sums) == 0) ||
        opts.echo) { // read stdin
        ret = sha512_stdin(&opts);
    }

    for (unsigned int i = 0; i < nbr_arg;) { // read files
        if (args[i] == NULL) {
            args++;
            continue;
        }
        func_ret = sha512_file(args[i], &opts);
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