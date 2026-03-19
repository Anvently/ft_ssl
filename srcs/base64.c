
#include <fcntl.h>
#include <ft_base64.h>
#include <unistd.h>

extern const char *executable_name;

static const t_options_base64 default_opts = {
    .mode = MODE_ENCODE, .input_file = NULL, .output_file = NULL};
static const char *usage = "\
usage: ./openssl base64 [flags]\n\
\n\
Flags:\n\
  -e, --encode          encode mode\n\
  -d, --decode          decode mode (default)\n\
  -i, --input=path      file to read from\n\
  -o, --output=path   	file to read to\n\
\n";

static const char alphabets[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+";

typedef struct s_base64_ctx {
    t_options_base64 opts;
    int fd_in;
    int fd_out;
} t_ctx;

static void free_ctx(t_ctx *ctx) {
    if (ctx->fd_in > 0)
        close(ctx->fd_in);
    if (ctx->fd_out > 0)
        close(ctx->fd_out);
}

static int open_io(t_ctx *ctx) {
    if (ctx->opts.input_file) {
        ctx->fd_in = open(ctx->opts.input_file, O_RDONLY, 0);
        if (ctx->fd_in < 0) {
            ft_sdprintf(1, "%s: base64: opening file: %s\n", executable_name,
                        strerror(errno));
            return (1);
        }
    }
    if (ctx->opts.output_file) {
        ctx->fd_out = open(ctx->opts.output_file, O_RDWR | O_CREAT, 0);
        if (ctx->fd_out < 0) {
            ft_sdprintf(1, "%s: base64: opening file: %s\n", executable_name,
                        strerror(errno));
            free_ctx(ctx);
            return (1);
        }
    }
    return (0);
}

static void encode_chunk(char chunk[3], size_t chunk_len, char out[4]) {

    ft_memcpy(out, &(char[4]){0, 0, '=', '='}, 4);
    switch (chunk_len) {
    case 1:
        out[0] = alphabets[chunk[0] >> 2];
        out[1] = alphabets[(chunk[0] & 0b11) << 4];
        break;

    case 2:
        out[0] = alphabets[chunk[0] >> 2];
        out[1] = alphabets[((chunk[0] & 0b11) << 4) | (chunk[1] >> 4)];
        out[2] = alphabets[(chunk[1] & 0b1111) << 2];
        break;

    case 3:
        out[0] = alphabets[chunk[0] >> 2];
        out[1] = alphabets[((chunk[0] & 0b11) << 4) | (chunk[1] >> 4)];
        out[2] = alphabets[((chunk[1] & 0b1111) << 2) | (chunk[2] >> 6)];
        out[3] = chunk[2] & 0b111111;
        break;
    }
}

static int base64_encode(t_ctx *ctx) {

    char chunk[3];
    char out[4];
    ssize_t nread;
    size_t chunk_len = 0;

    do {
        nread = read(ctx->fd_in, chunk + chunk_len, sizeof(chunk) - chunk_len);
        if (nread < 0) {
            ft_sdprintf(1, "%s: base64: reading from file: %s\n",
                        executable_name, strerror(errno));
            return (1);
        } else if (nread == 0) {
            break;
        } else if (nread == 3) {
            encode_chunk(chunk, 3, out);
            if (write(ctx->fd_out, out, 4) < 0)
                return (1);
            chunk_len = 0;
        } else {
            // Continue to read until EOF or 3 bytes
            chunk_len += nread;
        }
    } while (nread > 0);
    if (chunk_len > 0) {
        encode_chunk(chunk, chunk_len, out);
        if (write(ctx->fd_out, out, 4))
            return (1);
    }
    return (0);
}

static int base64_decode(t_ctx *ctx) {
    (void)ctx;
    return (0);
}

int base64(unsigned int nbr_arg, char **args) {
    t_ctx context = {
        .opts = default_opts, .fd_in = STDIN_FILENO, .fd_out = STDOUT_FILENO};
    int ret = 0;

    if (parse_base64_args(&nbr_arg, args, &context.opts))
        error(2, 0, "%s", usage);
    if (open_io(&context))
        return (1);
    if (context.opts.mode == MODE_ENCODE)
        ret = base64_encode(&context);
    else
        ret = base64_decode(&context);
    free_ctx(&context);
    return (ret);
}