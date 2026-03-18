#include <ft_md5.h>

#define TO_LITTLE_ENDIAN(n)                                                    \
    ((((u_int8_t *)&(n))[0] << 24) | (((u_int8_t *)&(n))[1] << 16) |           \
     (((u_int8_t *)&(n))[2] << 8) | (((u_int8_t *)&(n))[3] << 0))

extern const char *executable_name;

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
                       t_options_md5 *options) __attribute_maybe_unused__;
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

static u_int32_t left_rotate(u_int32_t n, u_int8_t off) {
    return ((n << off) | (n >> (32 - off)));
}

static u_int32_t init_state[4] = {0x67452301, 0xEFCDAB89, 0x98BADCFE,
                                  0x10325476};
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

void add_md5_block(u_int32_t state[4], const char block[64]) {
    u_int32_t new_state[4] = {state[0], state[1], state[2], state[3]};
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
        new_state[3] = new_state[2];
        new_state[2] = new_state[1];
        new_state[1] = left_rotate(new_state[0] + f + constants[i] +
                                       ((u_int32_t *)block)[g],
                                   rotates[i]) +
                       new_state[1];
        new_state[0] = tmp;
        // printf("Round %d: %#x, %#x, %#x, %#x\n", i, new_state[0],
        // new_state[1],
        //        new_state[2], new_state[3]);
    }
    state[0] += new_state[0];
    state[1] += new_state[1];
    state[2] += new_state[2];
    state[3] += new_state[3];
    // printf("OFFSET: %#x, %#x, %#x, %#x\n", new_state[0], new_state[1],
    //        new_state[2], new_state[3]);
}

static void hash_string(const char *str, u_int32_t digest[4]) {
    const size_t len = ft_strlen(str);
    size_t remaining = len;
    char padding[128] = {0};

    ft_memcpy(digest, init_state, sizeof(init_state));
    while (remaining >= 64) {
        add_md5_block(digest, str);
        remaining -= 128;
        str += 128;
    }
    ft_memcpy(padding, str, remaining);
    // add 1 bits after message (message is always % of 8 bits)
    padding[remaining] = 128; // 0b10000000
    if (64 - remaining < 8) {
        // Case where the minimum padding does not fit in a single block
        *((u_int64_t *)(padding + 128) - 1) = (len * 8);
        add_md5_block(digest, padding);
        add_md5_block(digest, padding + 64);
    } else {
        *((u_int64_t *)(padding + 64) - 1) = (len * 8);
        add_md5_block(digest, padding);
    }
    for (unsigned int i = 0; i < 4; i++)
        digest[i] = TO_LITTLE_ENDIAN(digest[i]);
}

static int hash_file(int fd, u_int32_t digest[4], bool echo) {
    ssize_t nread;
    size_t total_len = 0;
    char buff[64];
    char padding[128] = {0};

    ft_memcpy(digest, init_state, sizeof(init_state));
    total_len = nread = read(fd, buff, 64);
    if (echo && nread > 0 && write(1, buff, nread) < 0)
        return (1);
    while (nread == 64) {
        add_md5_block(digest, buff);
        nread = read(fd, buff, 64);
        total_len += nread;
        if (echo && nread > 0 && write(1, buff, nread) < 0)
            return (1);
    }
    if (nread < 0)
        return (1);
    ft_memcpy(padding, buff, nread);
    // add 1 bits after message (message is always % of 8 bits)
    padding[nread] = 128; // 0b10000000
    if (64 - nread < 8) {
        // Case where the minimum padding does not fit in a single block
        *((u_int64_t *)(padding + 128) - 1) = (total_len * 8);
        add_md5_block(digest, padding);
        add_md5_block(digest, padding + 64);
    } else {
        *((u_int64_t *)(padding + 64) - 1) = (total_len * 8);
        add_md5_block(digest, padding);
    }
    for (unsigned int i = 0; i < 4; i++)
        digest[i] = TO_LITTLE_ENDIAN(digest[i]);
    return (0);
}

static void print_hash(u_int32_t digest[4], const char *name, bool quote,
                       t_options_md5 *opts) {
    if (name == NULL)
        ft_sdprintf(1, "%x%x%x%x", digest[0], digest[1], digest[2], digest[3]);
    else if (opts->quiet == true)
        ft_sdprintf(1, "%x%x%x%x\n", digest[0], digest[1], digest[2],
                    digest[3]);
    else if (opts->reverse == false)
        ft_sdprintf(1, "MD5 (%c%s%c) = %x%x%x%x\n", quote ? '"' : 0, name,
                    quote ? '"' : 0, digest[0], digest[1], digest[2],
                    digest[3]);
    else
        ft_sdprintf(1, "%x%x%x%x %c%s%c\n", digest[0], digest[1], digest[2],
                    digest[3], quote ? '"' : 0, name, quote ? '"' : 0);
}

static void md5_string(const char *str, t_options_md5 *opts) {
    u_int32_t digest[4];

    hash_string(str, digest);
    print_hash(digest, str, true, opts);
}

static int md5_file(const char *path, t_options_md5 *opts) {
    u_int32_t digest[4];
    int fd = -1;

    fd = open(path, O_RDONLY, 0);
    if (fd < 0 || hash_file(fd, digest, false)) {
        ft_sdprintf(1, "%s: md5: %s: %s\n", executable_name, path,
                    strerror(errno));
        if (fd >= 0)
            close(fd);
        return (1);
    }
    close(fd);
    print_hash(digest, path, false, opts);
    return (0);
}

static int md5_stdin(t_options_md5 *opts) {
    u_int32_t digest[4];

    if (opts->reverse == false) {
        if (opts->echo) {
            ft_sdprintf(1, "MD5 (\"");
        } else
            ft_sdprintf(1, "MD5 (stdin) = ");
    }
    if (hash_file(0, digest, (opts->echo && opts->reverse == false))) {
        ft_sdprintf(1, "%s: md5: stdin: %s\n", executable_name,
                    strerror(errno));
        return (1);
    }
    if (opts->echo && opts->reverse == false) {
        ft_sdprintf(1, "\") = ");
        print_hash(digest, NULL, false, NULL);
        ft_sdprintf(1, "\n");
    } else if (opts->reverse == true) {
        print_hash(digest, NULL, false, NULL);
        ft_sdprintf(1, " stdin\n");
    } else {
        print_hash(digest, NULL, false, NULL);
        ft_sdprintf(1, "\n");
    }
    return (0);
}

int md5(unsigned int nbr_arg, char **args) {
    t_options_md5 opts = default_opts;
    int ret = 0, func_ret;

    if (parse_md5_args(&nbr_arg, args, &opts))
        error(2, 0, "%s", usage);
    if ((nbr_arg == 0 && ft_vector_size(opts.sums) == 0) ||
        opts.echo) { // read stdin
        ret = md5_stdin(&opts);
    }

    for (unsigned int i = 0; i < nbr_arg;) { // read files
        if (args[i] == NULL) {
            args++;
            continue;
        }
        func_ret = md5_file(args[i], &opts);
        if (func_ret)
            ret++;
        i++;
    }

    for (unsigned int i = 0; i < ft_vector_size(opts.sums); i++) {
        md5_string(opts.sums[i], &opts);
    }
    free_opts(&opts);
    return (ret);
}