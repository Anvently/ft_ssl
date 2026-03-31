#include <fcntl.h>
#include <ft_cipher.h>
#include <ft_des.h>
#include <ft_openssl_utils.h>
#include <ft_pbkdf.h>
#include <time.h>
#include <unistd.h>

/// STATIC STRUCT AND SYMBOL FOR PROGRAM

extern const char *executable_name;

static const t_options_des default_opts = {.mode = DES_MODE_ENCODE,
                                           .input_file = NULL,
                                           .output_file = NULL,
                                           .password.prompt = true,
                                           .des3 = true,
                                           .hash_option = "sha256"};
static const char *usage = "\
usage: ./openssl des3 [flags]\n\
\n\
Mode of operations: des3-cbc (default), des3-ecb, des3-pcbc, des3-cfb, des3-ofb\n\
\n\
Flags:\n\
  -a, --base64                  decode/encode the input/output in base64, depending on the encrypt mode\n\
  -e, --encode                  encode mode\n\
  -d, --decode                  decode mode (default)\n\
  -i, --input=path              file to read from\n\
  -o, --output=path             file to read to\n\
  -k, --key=key                 key in hex\n\
  -p, --input-pass              enable key/IV derivation from salt and given password\n\
  -s, --salt=salt               salt in hex\n\
  -v, --iv=iv                   initialization vector in hex\n\
      --md=sha256/md5/sha512    digest used to derive key and IV\n\
  -P, --print                   show salt, key and IV used\n\
\n ";

typedef struct s_des_ctx {
    t_options_des opts;
    char *payload;
    size_t payload_len;
    size_t remaining;
    char *cursor;
    int fd_out_base64; // Only use in encode with -a option enabled
    int fd_in_base64;  // Only use in encode with -a option enabled
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
    if (ctx->fd_in_base64 > 0)
        close(ctx->fd_in_base64);
    if (ctx->fd_out_base64 > 0)
        close(ctx->fd_out_base64);
}

static int input_base64_decode(int fd_in, int *new_fd_in) {
    int fds[2];

    if (pipe(fds)) {
        ft_sdprintf(2, "%s: des: using pipe() to decode base64 input: %s\n",
                    executable_name, strerror(errno));
        return (1);
    }
    if (base64_fds(fd_in, fds[1], BASE64_MODE_DECODE)) {
        close(fds[0]);
        close(fds[1]);
        return (1);
    }
    close(fds[1]);
    if (fd_in >= STDIN_FILENO)
        close(fd_in);
    close(fd_in);
    *new_fd_in = fds[0];
    return (0);
}

static int output_base64_encode(t_ctx *ctx) {
    int fds[2];

    if (pipe(fds)) {
        ft_sdprintf(2, "%s: des: using pipe() to decode base64 input: %s\n",
                    executable_name, strerror(errno));
        return (1);
    }
    ctx->fd_out_base64 = ctx->fd_out;
    ctx->fd_in_base64 = fds[0];
    ctx->fd_out = fds[1];
    return (0);
}

static int open_io(t_ctx *ctx) {
    int fd_in = STDIN_FILENO;

    if (ctx->opts.input_file) {
        fd_in = open(ctx->opts.input_file, O_RDONLY, 0);
        if (fd_in < 0) {
            ft_sdprintf(2, "%s: des: opening file: %s\n", executable_name,
                        strerror(errno));
            return (1);
        }
    }
    if (ctx->opts.base64 &&
        ctx->opts.mode == DES_MODE_DECODE) { // Decode payload to base64
        if (input_base64_decode(fd_in, &fd_in)) {
            if (fd_in != STDIN_FILENO)
                close(fd_in);
            return (1);
        }
    }
    if (read_file(fd_in, &ctx->payload)) {
        ft_sdprintf(2, "%s: des: reading file: %s\n", executable_name,
                    strerror(errno));
        if (fd_in != STDIN_FILENO)
            close(fd_in);
        return (1);
    }
    if (fd_in >= STDIN_FILENO)
        close(fd_in);
    ctx->payload_len = ft_vector_size(ctx->payload) - 1;
    ctx->cursor = ctx->payload;
    ctx->remaining = ctx->payload_len;
    if (ctx->opts.output_file) {
        ctx->fd_out =
            open(ctx->opts.output_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (ctx->fd_out < 0) {
            ft_sdprintf(2, "%s: des: opening file: %s\n", executable_name,
                        strerror(errno));
            free_ctx(ctx);
            return (1);
        }
    }
    if (ctx->opts.base64 &&
        ctx->opts.mode == DES_MODE_ENCODE) { // Encode cipher to base64
        if (output_base64_encode(ctx)) {
            free_ctx(ctx);
            return (1);
        }
    }
    return (0);
}

static void generate_keys(u_int64_t keys[16], u_int64_t key) {
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
}

static u_int64_t des3_algo_encrypt(u_int64_t block, u_int64_t keys[16]) {
    (void)block;
    (void)keys;
    return (0);
}

static u_int64_t des3_algo_decrypt(u_int64_t block, u_int64_t keys[16]) {
    (void)block;
    (void)keys;
    return (0);
}

static int des_encode(t_ctx *ctx) {
    u_int64_t keys[16];
    struct s_cipher_context cipher_ctx = {
        .data = keys,
        .decrypt_fun = (t_fun_cipher)des3_algo_decrypt,
        .encrypt_fun = (t_fun_cipher)des3_algo_encrypt,
        .enc_mode = ctx->opts.enc_mode,
        .fd_out = ctx->fd_out,
        .iv = htobe64(ctx->opts.iv.value),
        .name = "des3",
        .padlen = 0,
        .payload = ctx->cursor,
        .remaining = ctx->remaining};

    generate_keys(keys, ctx->opts.key.value.des);
    if (cipher_ctx.enc_mode == ENC_MODE_CBC ||
        cipher_ctx.enc_mode == ENC_MODE_ECB ||
        cipher_ctx.enc_mode == ENC_MODE_PCBC)
        cipher_ctx.padlen = 8;
    if (cipher_encrypt(&cipher_ctx))
        return (1);
    if (ctx->opts.base64) {
        close(ctx->fd_out);
        if (base64_fds(ctx->fd_in_base64, ctx->fd_out_base64,
                       BASE64_MODE_ENCODE))
            return (1);
    }
    return (0);
}

static int des_decode(t_ctx *ctx) {
    u_int64_t keys[16];
    struct s_cipher_context cipher_ctx = {
        .data = keys,
        .decrypt_fun = (t_fun_cipher)des3_algo_decrypt,
        .encrypt_fun = (t_fun_cipher)des3_algo_encrypt,
        .enc_mode = ctx->opts.enc_mode,
        .fd_out = ctx->fd_out,
        .iv = htobe64(ctx->opts.iv.value),
        .name = "des3",
        .padlen = 0,
        .payload = ctx->cursor,
        .remaining = ctx->remaining};

    generate_keys(keys, ctx->opts.key.value.des);
    if (cipher_ctx.enc_mode == ENC_MODE_CBC ||
        cipher_ctx.enc_mode == ENC_MODE_ECB ||
        cipher_ctx.enc_mode == ENC_MODE_PCBC)
        cipher_ctx.padlen = 8;
    if (cipher_decrypt(&cipher_ctx))
        return (1);
    return (0);
}

static int write_salt(int fd, u_int64_t salt) {
    char buff[16] = "Salted__";

    salt = htobe64(salt);
    ((u_int64_t *)buff)[1] = salt;
    if (write(fd, &buff[0], sizeof(buff)) < 0) {
        ft_sdprintf(2, "%s: des: writing salt: %s\n", executable_name,
                    strerror(errno));
        return (1);
    }
    return (0);
}

static int read_salt(const char *payload, size_t payload_len, u_int64_t *salt) {

    if (payload_len < 16) {
        ft_sdprintf(2, "%s: des: reading salt: invalid salt len\n",
                    executable_name);
        return (1);
    }
    if (ft_strncmp(payload, "Salted__", 8) != 0) {
        ft_sdprintf(2, "%s: des: reading salt: invalid salt header\n",
                    executable_name);
        return (1);
    }
    *salt = ((u_int64_t *)payload)[1];
    *salt = htobe64(*salt);
    return (0);
}

static int derive_key(t_ctx *ctx) {
    char dk[16];
    // GENERATE KEY
    // 1. Generate / read salt
    if (ctx->opts.mode == DES_MODE_ENCODE) {
        // @todo generate salt
        if (ctx->opts.salt.given == false)
            ctx->opts.salt.value = random_u64();
        if (write_salt(ctx->fd_out, ctx->opts.salt.value))
            return (1);
    } else if (ctx->opts.mode == DES_MODE_DECODE) {
        if (read_salt(ctx->payload, ctx->payload_len, &ctx->opts.salt.value))
            return (1);
        ctx->cursor += 16;
        ctx->remaining -= 16;
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
        ft_sdprintf(2, "%s: des: %s: invalid hash option\n", executable_name,
                    ctx->opts.hash_option);
        return (1);
    }
    pbkdf1(&args);
    ctx->opts.key.value.des = htobe64(*(u_int64_t *)dk);
    if (ctx->opts.iv.given == false)
        ctx->opts.iv.value = htobe64(*(((u_int64_t *)dk) + 1));
    return (0);
}

int des3(unsigned int nbr_arg, char **args, enum e_encryption_mode mode) {
    t_ctx context = {
        .opts = default_opts, .payload = NULL, .fd_out = STDOUT_FILENO};
    int ret = 0;

    context.opts.enc_mode = mode;
    if (parse_des_args(&nbr_arg, args, &context.opts))
        error(2, 0, "%s", usage);
    if (open_io(&context))
        return (1);
    if (context.opts.key.given == false && derive_key(&context)) {
        free_ctx(&context);
        return (1);
    }
    if (context.opts.print_key) {
        ft_sdprintf(2, "salt=%lX\nkey=%lX\n", context.opts.salt.value,
                    context.opts.key.value);
        if (context.opts.enc_mode != ENC_MODE_ECB)
            ft_sdprintf(2, "IV=%lX\n", context.opts.iv.value);
    }
    if (context.opts.mode == DES_MODE_ENCODE)
        ret = des_encode(&context);
    else
        ret = des_decode(&context);
    free_ctx(&context);
    return (ret);
}

int des3_ecb(unsigned int nbr_arg, char **args) {
    return (des3(nbr_arg, args, ENC_MODE_ECB));
}

int des3_cbc(unsigned int nbr_arg, char **args) {
    return (des3(nbr_arg, args, ENC_MODE_CBC));
}

int des3_pcbc(unsigned int nbr_arg, char **args) {
    return (des3(nbr_arg, args, ENC_MODE_PCBC));
}

int des3_cfb(unsigned int nbr_arg, char **args) {
    return (des3(nbr_arg, args, ENC_MODE_CFB));
}

int des3_ofb(unsigned int nbr_arg, char **args) {
    return (des3(nbr_arg, args, ENC_MODE_OFB));
}
