#include <errno.h>
#include <fcntl.h>
#include <ft_base64.h>
#include <ft_openssl_utils.h>

extern const char *executable_name;

int read_file(int fd, char **vec) {
    ssize_t nread;
    size_t size = 0;
    size_t capacity = 1024;

    *vec = ft_vector_create(sizeof(char), capacity);
    if (*vec == NULL)
        return (1);
    size = nread = read(fd, *vec + size, capacity - 1);
    while (nread > 0) {
        if (size == (capacity - 1)) {
            capacity *= 2;
            if (ft_vector_reserve((t_vector **)vec, capacity)) {
                ft_vector_free((t_vector **)vec);
                return (1);
            }
        }
        nread = read(fd, *vec + size, capacity - (size + 1));
        size += nread;
    }
    if (nread < 0) {
        ft_vector_free((t_vector **)vec);
        return (1);
    }
    (*vec)[size] = '\0';
    ft_vector_resize((t_vector **)vec, size + 1);
    return (0);
}

int print_character_64(int fd, const char *buff, unsigned int n) {
    static size_t nprint = 0;
    ssize_t nwrite;

    nwrite = write(fd, buff, ft_min_lu(n, 64 - nprint));
    if (nwrite < 0)
        return (1);
    nprint += nwrite;
    if (nprint == 64) {
        ft_sdprintf(fd, "\n");
        nprint = 0;
    }
    if (n > (unsigned int)nwrite)
        return (print_character_64(fd, buff + nwrite, n - nwrite));
    return (0);
}

static int input_base64_decode(int fd_in, int *new_fd_in) {
    int fds[2];

    if (pipe(fds)) {
        ft_sdprintf(2, "%s: using pipe() to decode base64 input: %s\n",
                    executable_name, strerror(errno));
        return (1);
    }
    if (base64_fds(fd_in, fds[1], OP_MODE_DECODE)) {
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

static int output_base64_init(struct s_io_context *ctx) {
    int fds[2];

    if (pipe(fds)) {
        ft_sdprintf(2, "%s: using pipe() to decode base64 input: %s\n",
                    executable_name, strerror(errno));
        return (1);
    }
    ctx->fd_out_base64 = ctx->fd_out;
    ctx->fd_in_base64 = fds[0];
    ctx->fd_out = fds[1];
    return (0);
}

void io_free(struct s_io_context *ctx) {
    if (ctx->payload != NULL)
        ft_vector_free((t_vector **)&ctx->payload);
    if (ctx->fd_out > 0)
        close(ctx->fd_out);
    if (ctx->fd_in_base64 > 0)
        close(ctx->fd_in_base64);
    if (ctx->fd_out_base64 > 0)
        close(ctx->fd_out_base64);
}

int io_open(struct s_io_context *ctx) {

    if (ctx->input_file) {
        ctx->fd_in = open(ctx->input_file, O_RDONLY, 0);
        if (ctx->fd_in < 0) {
            ft_sdprintf(2, "%s: opening file: %s\n", executable_name,
                        strerror(errno));
            return (1);
        }
    }
    if (ctx->options.base64 &&
        ctx->options.mode == OP_MODE_DECODE) { // Decode payload to base64
        if (input_base64_decode(ctx->fd_in, &ctx->fd_in)) {
            io_free(ctx);
            return (1);
        }
    }
    if (read_file(ctx->fd_in, &ctx->payload)) {
        ft_sdprintf(2, "%s: reading file: %s\n", executable_name,
                    strerror(errno));
        io_free(ctx);
        return (1);
    }
    if (ctx->fd_in >= STDIN_FILENO)
        close(ctx->fd_in);
    ctx->payload_len = ft_vector_size(ctx->payload) - 1;
    ctx->cursor = ctx->payload;
    ctx->remaining = ctx->payload_len;
    if (ctx->output_file) {
        ctx->fd_out = open(ctx->output_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (ctx->fd_out < 0) {
            ft_sdprintf(2, "%s: opening file: %s\n", executable_name,
                        strerror(errno));
            io_free(ctx);
            return (1);
        }
    }
    if (ctx->options.base64 &&
        ctx->options.mode == OP_MODE_ENCODE) { // Init base64 cipher encoding
        if (output_base64_init(ctx)) {
            io_free(ctx);
            return (1);
        }
    }
    return (0);
}

int io_base64_encode(struct s_io_context *ctx) {
    close(ctx->fd_out);
    if (base64_fds(ctx->fd_in_base64, ctx->fd_out_base64, OP_MODE_ENCODE))
        return (1);
    return (0);
}

int io_base64_decode(struct s_io_context *ctx) {
    if (input_base64_decode(ctx->fd_in, &ctx->fd_in))
        return (1);
    return (0);
}