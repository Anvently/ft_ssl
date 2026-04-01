#include <fcntl.h>
#include <ft_cipher.h>
#include <ft_des.h>
#include <ft_openssl_utils.h>
#include <ft_pbkdf.h>
#include <time.h>
#include <unistd.h>

/// STATIC STRUCT AND SYMBOL FOR PROGRAM

extern const char *executable_name;

static const t_options_des default_opts = {.mode = OP_MODE_ENCODE,
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

typedef struct s_des3_ctx {
    t_options_des opts;
    struct s_io_context io;
} t_ctx;

static u_int64_t des3_algo_encrypt(u_int64_t block, u_int64_t keys[3][16]) {
    block = des_algo_encrypt(block, keys[0]);
    block = des_algo_decrypt(block, keys[1]);
    block = des_algo_encrypt(block, keys[2]);
    return (block);
}

static u_int64_t des3_algo_decrypt(u_int64_t block, u_int64_t keys[3][16]) {
    block = des_algo_decrypt(block, keys[0]);
    block = des_algo_encrypt(block, keys[1]);
    block = des_algo_decrypt(block, keys[2]);
    return (block);
}

static void des3_gen_keys(u_int64_t keys[3][16], unsigned char pkey[24]) {
    des_gen_keys(keys[0], htobe64(((u_int64_t *)pkey)[0]));
    des_gen_keys(keys[1], htobe64(((u_int64_t *)pkey)[1]));
    des_gen_keys(keys[2], htobe64(((u_int64_t *)pkey)[2]));
}

static int des3_encode(t_ctx *ctx) {
    u_int64_t keys[3][16] = {0};
    struct s_cipher_context cipher_ctx = {
        .data = keys,
        .decrypt_fun = (t_fun_cipher)des3_algo_decrypt,
        .encrypt_fun = (t_fun_cipher)des3_algo_encrypt,
        .enc_mode = ctx->opts.enc_mode,
        .fd_out = ctx->io.fd_out,
        .iv = htobe64(ctx->opts.iv.value),
        .name = "des3",
        .padlen = 0,
        .payload = ctx->io.cursor,
        .remaining = ctx->io.remaining};

    des3_gen_keys(keys, ctx->opts.key.value.des3);
    if (cipher_ctx.enc_mode == ENC_MODE_CBC ||
        cipher_ctx.enc_mode == ENC_MODE_ECB ||
        cipher_ctx.enc_mode == ENC_MODE_PCBC)
        cipher_ctx.padlen = 8;
    if (cipher_encrypt(&cipher_ctx))
        return (1);
    if (ctx->opts.base64 && io_base64_encode(&ctx->io))
        return (1);
    return (0);
}

static int des3_decode(t_ctx *ctx) {
    u_int64_t keys[3][16];
    struct s_cipher_context cipher_ctx = {
        .data = keys,
        .decrypt_fun = (t_fun_cipher)des3_algo_decrypt,
        .encrypt_fun = (t_fun_cipher)des3_algo_encrypt,
        .enc_mode = ctx->opts.enc_mode,
        .fd_out = ctx->io.fd_out,
        .iv = htobe64(ctx->opts.iv.value),
        .name = "des3",
        .padlen = 0,
        .payload = ctx->io.cursor,
        .remaining = ctx->io.remaining};

    des3_gen_keys(keys, ctx->opts.key.value.des3);
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
        ft_sdprintf(2, "%s: des3: writing salt: %s\n", executable_name,
                    strerror(errno));
        return (1);
    }
    return (0);
}

static int read_salt(const char *payload, size_t payload_len, u_int64_t *salt) {

    if (payload_len < 16) {
        ft_sdprintf(2, "%s: des3: reading salt: invalid salt len\n",
                    executable_name);
        return (1);
    }
    if (ft_strncmp(payload, "Salted__", 8) != 0) {
        ft_sdprintf(2, "%s: des3: reading salt: invalid salt header\n",
                    executable_name);
        return (1);
    }
    *salt = ((u_int64_t *)payload)[1];
    *salt = htobe64(*salt);
    return (0);
}

static int derive_key(t_ctx *ctx) {
    char dk[32];
    // GENERATE KEY
    // 1. Generate / read salt
    if (ctx->opts.mode == OP_MODE_ENCODE) {
        if (ctx->opts.salt.given == false)
            ctx->opts.salt.value = random_u64();
        if (write_salt(ctx->io.fd_out, ctx->opts.salt.value))
            return (1);
    } else if (ctx->opts.mode == OP_MODE_DECODE) {
        if (read_salt(ctx->io.payload, ctx->io.payload_len,
                      &ctx->opts.salt.value))
            return (1);
        ctx->io.cursor += 16;
        ctx->io.remaining -= 16;
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
    if (args.hash_opts == NULL || ft_strcmp(args.hash_opts->name, "md5") == 0) {
        ft_sdprintf(2, "%s: des3: %s: invalid hash option\n", executable_name,
                    ctx->opts.hash_option);
        return (1);
    }
    pbkdf1(&args);
    ft_memcpy(ctx->opts.key.value.des3, dk, sizeof(ctx->opts.key.value.des3));
    if (ctx->opts.iv.given == false)
        ctx->opts.iv.value = htobe64(*(((u_int64_t *)dk) + 3)); // LE
    return (0);
}

static void print_keys(t_ctx *ctx) {
    char out[2];

    ft_sdprintf(2, "salt=%lX\nkey=", ctx->opts.salt.value);
    for (unsigned int i = 0; i < sizeof(ctx->opts.key.value.des3); i++) {
        ft_bin2hex(ctx->opts.key.value.des3[i], out);
        write(2, out, 2);
    }
    write(2, "\n", 1);
    if (ctx->opts.enc_mode != ENC_MODE_ECB)
        ft_sdprintf(2, "IV=%lX\n", ctx->opts.iv.value);
}

int des3(unsigned int nbr_arg, char **args, enum e_encryption_mode mode) {
    t_ctx context = {.opts = default_opts,
                     .io = {.fd_out = STDOUT_FILENO, .fd_in = STDIN_FILENO}};
    int ret = 0;

    context.opts.enc_mode = mode;
    if (parse_des_args(&nbr_arg, args, &context.opts))
        error(2, 0, "%s", usage);
    context.io.options.base64 = context.opts.base64;
    context.io.options.mode = context.opts.mode;
    context.io.input_file = context.opts.input_file;
    context.io.output_file = context.opts.output_file;
    if (io_open(&context.io))
        return (1);
    if (context.opts.key.given == false && derive_key(&context)) {
        io_free(&context.io);
        return (1);
    }
    if (context.opts.print_key)
        print_keys(&context);
    if (context.opts.mode == OP_MODE_ENCODE)
        ret = des3_encode(&context);
    else
        ret = des3_decode(&context);
    io_free(&context.io);
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
