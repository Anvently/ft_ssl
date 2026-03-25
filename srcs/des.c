#include <fcntl.h>
#include <ft_des.h>
#include <ft_openssl_utils.h>
#include <ft_pbkdf.h>
#include <time.h>
#include <unistd.h>

extern const char *executable_name;

static const t_options_des default_opts = {.mode = MODE_ENCODE,
                                           .input_file = NULL,
                                           .output_file = NULL,
                                           .password.prompt = true};
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

static int des_encode(t_ctx *ctx) {
    (void)ctx;
    return (0);
}
static int des_decode(t_ctx *ctx) {
    (void)ctx;
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
    struct s_pbkdf_arg args = {.dk_len = 16,
                               .iteration = 1,
                               .hash_opts = get_hash_props("md5"),
                               .key_out = &ctx->opts.key,
                               .password = ctx->opts.password.value,
                               .password_len =
                                   ft_strlen(ctx->opts.password.value),
                               .salt = htobe64(ctx->opts.salt.value)};
    pbkdf1(&args);
    ft_sdprintf(1, "salt=%lx\nkey=%lx\n", ctx->opts.salt.value,
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