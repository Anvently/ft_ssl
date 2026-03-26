#include <fcntl.h>
#include <ft_des.h>
#include <ft_openssl_utils.h>
#include <ft_pbkdf.h>
#include <time.h>
#include <unistd.h>

/// STATIC STRUCT AND SYMBOL FOR PROGRAM

extern const char *executable_name;

static const t_options_des default_opts = {.mode = MODE_ENCODE,
                                           .input_file = NULL,
                                           .output_file = NULL,
                                           .password.prompt = true,
                                           .hash_option = "md5"};
static const char *usage = "\
usage: ./openssl base64 [flags]\n\
\n\
Flags:\n\
  -a, --base64          decode/encode the input/output in base64, depending on the encrypt mode\n\
  -e, --encode          encode mode\n\
  -d, --decode          decode mode (default)\n\
  -i, --input=path      file to read from\n\
  -o, --output=path     file to read to\n\
  -k, --key=key         key in hex\n\
  -p, --input-pass      enable key/IV derivation from salt and given password\n\
      --pass            input password from command line instead of stdin\n\
  -s, --salt            salt in hex\n\
  -v, --iv              initialization vector in hex\n\
\n ";

typedef struct s_des_ctx {
    t_options_des opts;
    char *payload;
    char *cursor;
    size_t payload_len;
    int fd_out;
} t_ctx;

/// STATIC CONSTANT FOR DES ALGORITHM

// clang-format off
static const u_int8_t pc1[] = {
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
};

static const u_int8_t pc2[] = {
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
};

static const u_int8_t ip[] = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
};

static const u_int8_t fp[] = {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
};

static const u_int8_t shifts[] = {
        1, 1, 2, 2,
        2, 2, 2, 2,
        1, 2, 2, 2,
        2, 2, 2, 1
};

// clang-format on

static void free_ctx(t_ctx *ctx) {
    if (ctx->payload != NULL)
        ft_vector_free((t_vector **)&ctx->payload);
    if (ctx->fd_out > 0)
        close(ctx->fd_out);
}

static int open_io(t_ctx *ctx) {
    int fd = STDIN_FILENO;

    if (ctx->opts.input_file) {
        fd = open(ctx->opts.input_file, O_RDONLY, 0);
        if (fd < 0) {
            ft_sdprintf(1, "%s: des: opening file: %s\n", executable_name,
                        strerror(errno));
            return (1);
        }
    }
    if (read_file(fd, &ctx->payload)) {
        ft_sdprintf(1, "%s: des: reading file: %s\n", executable_name,
                    strerror(errno));
        return (1);
    }
    ctx->payload_len = ft_vector_size(ctx->payload) - 1;
    ctx->cursor = ctx->payload;
    if (ctx->opts.output_file) {
        ctx->fd_out =
            open(ctx->opts.output_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (ctx->fd_out < 0) {
            ft_sdprintf(1, "%s: des: opening file: %s\n", executable_name,
                        strerror(errno));
            free_ctx(ctx);
            return (1);
        }
    }
    return (0);
}

static void generate_keys(u_int64_t keys[16], u_int64_t key,
                          enum e_op_mode mode) {
    u_int32_t left, right;
    u_int64_t pkey = permute(key, pc1, sizeof(pc1)) >> 8; // 64 to 56 bits

    left = (u_int32_t)(pkey >> 28);        // 28 bits
    right = (u_int32_t)(pkey & 0xFFFFFFF); // 28 bits
    for (unsigned int i = 0; i < 16; i++) {
        right = left_rotate28(right, shifts[i]);
        left = left_rotate28(left, shifts[i]);
        pkey = ((u_int64_t)left << 28) | right;               // 56 bits concat
        keys[i] = permute(pkey << 8, pc2, sizeof(pc2)) >> 16; // 56 to 48 bits
    }
    if (mode == MODE_DECODE) { // reverse keys
        for (unsigned int i = 0; i < 8; i++) {
            pkey = keys[i];
            keys[i] = keys[15 - i];
            keys[15 - i] = pkey;
        }
    }
}

static int des_encode(t_ctx *ctx) {
    (void)fp;
    (void)ip;
    u_int64_t keys[16];
    generate_keys(keys, ctx->opts.key.value, MODE_ENCODE);
    return (0);
}
static int des_decode(t_ctx *ctx) {
    u_int64_t keys[16];
    generate_keys(keys, ctx->opts.key.value, MODE_DECODE);
    return (0);
}

static int write_salt(int fd, u_int64_t salt) {
    char buff[16] = "Salted__";

    salt = REVERT_ENDIANESS_64(salt);
    ((u_int64_t *)buff)[1] = salt;
    if (write(fd, &buff[0], sizeof(buff)) < 0) {
        ft_sdprintf(1, "%s: des: writing salt: %s\n", executable_name,
                    strerror(errno));
        return (1);
    }
    return (0);
}

static int read_salt(const char *payload, size_t payload_len, u_int64_t *salt) {

    if (payload_len < 16) {
        ft_sdprintf(1, "%s: des: reading salt: invalid salt len\n",
                    executable_name);
        return (1);
    }
    if (ft_strncmp(payload, "Salted__", 8) != 0) {
        ft_sdprintf(1, "%s: des: reading salt: invalid salt header\n",
                    executable_name);
        return (1);
    }
    *salt = ((u_int64_t *)payload)[1];
    *salt = REVERT_ENDIANESS_64(*salt);
    return (0);
}

static int derive_key(t_ctx *ctx) {
    char dk[8];
    // GENERATE KEY
    // 1. Generate / read salt
    if (ctx->opts.mode == MODE_ENCODE) {
        // @todo generate salt
        if (ctx->opts.salt.given == false)
            ctx->opts.salt.value = random_u64();
        if (write_salt(ctx->fd_out, ctx->opts.salt.value))
            return (1);
    } else if (ctx->opts.mode == MODE_DECODE) {
        if (read_salt(ctx->payload, ctx->payload_len, &ctx->opts.salt.value))
            return (1);
        ctx->cursor += 16;
    }
    // 2. Derive key and IV from salt and password
    struct s_pbkdf_arg args = {
        .dk_len = sizeof(dk),
        .iteration = 1,
        .hash_opts = get_hash_props(ctx->opts.hash_option),
        .password = ctx->opts.password.value,
        .password_len = ft_strlen(ctx->opts.password.value),
        .salt = htobe64(ctx->opts.salt.value),
        .dk_out = dk};
    if (args.hash_opts == NULL) {
        ft_sdprintf(1, "%s: des: %s: invalid hash option\n", executable_name,
                    ctx->opts.hash_option);
        return (1);
    }
    pbkdf1(&args);
    ctx->opts.key.value = htobe64(*(u_int64_t *)dk);
    ft_sdprintf(1, "salt=%lX\nkey=%lX\n", ctx->opts.salt.value,
                ctx->opts.key.value);

    return (0);
}

int des(unsigned int nbr_arg, char **args) {
    t_ctx context = {
        .opts = default_opts, .payload = NULL, .fd_out = STDOUT_FILENO};
    int ret = 0;

    if (parse_des_args(&nbr_arg, args, &context.opts))
        error(2, 0, "%s", usage);
    if (open_io(&context))
        return (1);
    if (context.opts.key.given == false && derive_key(&context)) {
        free_ctx(&context);
        return (1);
    }
    if (context.opts.mode == MODE_ENCODE)
        ret = des_encode(&context);
    else
        ret = des_decode(&context);
    free_ctx(&context);
    return (ret);
}