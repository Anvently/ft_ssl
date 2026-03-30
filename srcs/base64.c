
#include <fcntl.h>
#include <ft_base64.h>
#include <ft_openssl_utils.h>
#include <unistd.h>

extern const char *executable_name;

static const t_options_base64 default_opts = {
    .mode = BASE64_MODE_ENCODE, .input_file = NULL, .output_file = NULL};
static const char *usage = "\
usage: ./openssl base64 [flags]\n\
\n\
Flags:\n\
  -e, --encode          encode mode\n\
  -d, --decode          decode mode (default)\n\
  -i, --input=path      file to read from\n\
  -o, --output=path   	file to read to\n\
\n";

#define INVALID_CHARACTER ((char)sizeof(alphabets))
#define PADDING_CHARACTER ((char)64)
static const char alphabets[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

typedef struct s_base64_ctx {
    t_options_base64 opts;
    char *payload;
    int fd_out;
    int fd_in;
} t_ctx;

static void free_ctx(t_ctx *ctx) {
    if (ctx->payload != NULL)
        ft_vector_free((t_vector **)&ctx->payload);
    if (ctx->fd_out > 0)
        close(ctx->fd_out);
}

static int open_io(t_ctx *ctx) {
    int fd = ctx->fd_in;

    if (ctx->opts.input_file) {
        fd = open(ctx->opts.input_file, O_RDONLY, 0);
        if (fd < 0) {
            ft_sdprintf(1, "%s: base64: opening file: %s\n", executable_name,
                        strerror(errno));
            return (1);
        }
    }
    if (read_file(fd, &ctx->payload)) {
        ft_sdprintf(1, "%s: base64: reading file: %s\n", executable_name,
                    strerror(errno));
        return (1);
    }
    if (ctx->opts.output_file) {
        ctx->fd_out =
            open(ctx->opts.output_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (ctx->fd_out < 0) {
            ft_sdprintf(1, "%s: base64: opening file: %s\n", executable_name,
                        strerror(errno));
            free_ctx(ctx);
            return (1);
        }
    }
    return (0);
}

static void encode_chunk(const char chunk[3], size_t chunk_len, char out[4]) {
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
        out[3] = alphabets[chunk[2] & 0b111111];
        break;
    }
}

static u_int8_t base64idx(char c) {
    for (u_int8_t i = 0; i < (u_int8_t)sizeof(alphabets); i++) {
        if (alphabets[i] == c)
            return i;
    }
    return (INVALID_CHARACTER);
}
// clang-format off
/* 

4               |5               | 8               | \ n                        ASCII
5 2             |5 3             | 5 6             | 1 0                        ASCII_INT
0 0 1 1 0 1 0 0 |0 0 1 1 0 1 0 1 | 0 0 1 1 1 0 0 0 | 0 0 0 0 1 0 1 0            BINARY
0 0 1 1 0 1|0 0  0 0 1 1|0 1 0 1   0 0|1 1 1 0 0 0 | 0 0 0 0 1 0|1 0 - - - -    BINARY
1 3        |3           |20           |56          |2           |32  ...        BASE64_INT
N           D            U             4            C            g  = =         BASE64_ALPHABET

=> NDU4Cg==
*/
// clang-format on

static int decode_chunk(const char payload[4], char out[3]) {
    u_int8_t chunk[4] = {base64idx(payload[0]), base64idx(payload[1]),
                         base64idx(payload[2]), base64idx(payload[3])};

    if (chunk[0] == INVALID_CHARACTER || chunk[1] == INVALID_CHARACTER ||
        chunk[2] == INVALID_CHARACTER || chunk[3] == INVALID_CHARACTER)
        return (-1);
    if (chunk[2] == PADDING_CHARACTER) {
        if (chunk[3] != PADDING_CHARACTER)
            return (-1);
        // 2 PADDING
        /*N           D            =         =         BASE64_ALPHABET
          1 3        |3           |                    BASE64_INT
          0 0 1 1 0 1|0 0  0 0 1 1|                    BINARY BASE64
          0 0 1 1 0 1 0 0 |0 0 1 1 0 0 0 0 |           BINARY
          5 2             |5 3             |           ASCII_INT
          4               |5               |           ASCII */
        out[0] = (chunk[0] << 2) | (chunk[1] >> 4); // ok
        out[1] = 0;                                 // ok
        out[2] = 0;
        return (1);
    }
    if (chunk[3] == PADDING_CHARACTER) {
        // 1 PADDING
        /*N           D            U            =      BASE64_ALPHABET
          1 3        |3           |20                  BASE64_INT
          0 0 1 1 0 1|0 0  0 0 1 1|0 1 0 1 0 0|        BINARY BASE64
          0 0 1 1 0 1 0 0 |0 0 1 1 0 1 0 1 |           BINARY
          5 2             |5 3             |           ASCII_INT
          4               |5               |           ASCII */
        out[0] = (chunk[0] << 2) | (chunk[1] >> 4);            // ok
        out[1] = ((chunk[1] & 0b1111) << 4) | (chunk[2] >> 2); // ok
        out[2] = 0;                                            // ok
        return (2);
    }
    // NO PADDING
    /* N           D            U          |4             BASE64_ALPHABET
       1 3        |3           |20         |56            BASE64_INT
       0 0 1 1 0 1|0 0  0 0 1 1|0 1 0 1 0 0|1 1 1 0 0 0   BINARY BASE64
       0 0 1 1 0 1 0 0 |0 0 1 1 0 1 0 1|0 0 1 1 1 0 0 0   BINARY
       5 2             |5 3            |56                ASCII_INT
       4               |5              |8                 ASCII
 */
    out[0] = (chunk[0] << 2) | (chunk[1] >> 4);            // ok
    out[1] = ((chunk[1] & 0b1111) << 4) | (chunk[2] >> 2); // ok
    out[2] = ((chunk[2] & 0b11) << 6) | chunk[3];          // ok
    return (3);
}

static int base64_encode(t_ctx *ctx) {

    const char *payload = ctx->payload;
    size_t payload_size = ft_vector_size(ctx->payload) - 1;
    char out[4];

    while (payload_size >= 3) {
        encode_chunk(payload, 3, out);
        if (print_character_64(ctx->fd_out, out, 4)) {
            ft_sdprintf(1, "%s: base64: writing to file: %s\n", executable_name,
                        strerror(errno));
            return (1);
        }
        payload_size -= 3;
        payload += 3;
    }
    if (payload_size) {
        encode_chunk(payload, payload_size, out);
        if (print_character_64(ctx->fd_out, out, 4)) {
            ft_sdprintf(1, "%s: base64: writing to file: %s\n", executable_name,
                        strerror(errno));
            return (1);
        }
    }
    ft_sdprintf(ctx->fd_out, "\n");
    return (0);
}

static int base64_decode(t_ctx *ctx) {

    const char *payload = ctx->payload;
    size_t payload_size = ft_vector_size(ctx->payload) - 1;
    char out[3];
    int len_out;

    for (size_t i = 0; i < payload_size; i += 4) {
        while (((payload[i] == '\n') || (payload[i] == '\r')) &&
               i < payload_size)
            i++;
        if (i == payload_size)
            break;
        if ((len_out = decode_chunk(payload + i, out)) < 0) {
            ft_sdprintf(1, "%s: base64: invalid input\n", executable_name);
            return (1);
        }
        if (write(ctx->fd_out, out, len_out) < 0) {
            ft_sdprintf(1, "%s: base64: writing to file: %s\n", executable_name,
                        strerror(errno));
            return (1);
        }
    }
    // ft_sdprintf(1, "\n");
    return (0);
}

int base64_fds(int fd_in, int fd_out, enum e_base64_mode mode) {
    t_ctx context = {.opts = default_opts,
                     .payload = NULL,
                     .fd_out = fd_out,
                     .fd_in = fd_in};
    int ret = 0;

    context.opts.mode = mode;
    if (open_io(&context))
        return (1);
    if (context.opts.mode == BASE64_MODE_ENCODE)
        ret = base64_encode(&context);
    else
        ret = base64_decode(&context);
    free_ctx(&context);
    return (ret);
}

int base64(unsigned int nbr_arg, char **args) {
    t_ctx context = {.opts = default_opts,
                     .payload = NULL,
                     .fd_out = STDOUT_FILENO,
                     .fd_in = STDIN_FILENO};
    int ret = 0;

    if (parse_base64_args(&nbr_arg, args, &context.opts))
        error(2, 0, "%s", usage);
    if (open_io(&context))
        return (1);
    if (context.opts.mode == BASE64_MODE_ENCODE)
        ret = base64_encode(&context);
    else
        ret = base64_decode(&context);
    free_ctx(&context);
    return (ret);
}