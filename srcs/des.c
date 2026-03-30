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
    size_t payload_len;
    size_t remaining;
    char *cursor;
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

static const u_int8_t   expp[] = {
        32, 1, 2, 3, 4, 5, 4, 5,
        6, 7, 8, 9, 8, 9, 10, 11,
        12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21,
        22, 23, 24, 25, 24, 25, 26, 27,
        28, 29, 28, 29, 30, 31, 32, 1
};

static const u_int8_t   sboxes[8][16 * 4] = {
    [0] = {
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
    },
    [1] = {
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
    },
    [2] = {
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
    },
    [3] = {
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
    },
    [4] = {
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
    },
    [5] = {
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
    },
    [6] = {
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
    },
    [7] = {
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
    }
};

static const u_int8_t per[] = {
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
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
    ctx->remaining = ctx->payload_len;
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
/*
010110 100011 101110 110000 010010 000011 001111 001111

*/
static u_int64_t mangler_function(u_int64_t right, u_int64_t key) {
    // EXPANSION from 32 to 48 bits
    u_int32_t subst = 0;
    right = permute(right << 32, expp, sizeof(expp)) >> 16;
    // right is left-padded : 0000[XXXXXXXXXXXX]
    right ^= key; // XOR right with 48-bits sub-key
    // SUBSTITUTION : 48 to 32 bits
    for (unsigned int i = 0; i < 8; i++) { // Split into 8 chunk of 6 bits
        u_int8_t row_idx, col_idx;
        u_int8_t chunk = (right >> (48 - ((i + 1) * 6))) & 0b111111;

        // FInd result in matrice
        row_idx = ((chunk >> 4) & 0b10) | (chunk & 0x1);
        col_idx = (chunk >> 1) & 0xF;
        chunk = sboxes[i][row_idx * 16 + col_idx];
        subst = (subst << 4) | chunk;
    }
    // TRANSPOSITION
    right = permute((u_int64_t)subst << 32, per, sizeof(per)) >> 32;
    return (right);
}

static u_int64_t des_encode_decode_block(u_int64_t padded_payload,
                                         u_int64_t keys[16], u_int64_t *iv) {
    u_int64_t block, left, right, tmp;

    block = htobe64(padded_payload); // Revert endianness (payload is big endian
                                     // while uint64_t is little endian)
    if (iv)
        block ^= *iv;
    block = permute(block, ip, sizeof(ip)); // initial permutation
    left = block >> 32;
    right = block & 0xFFFFFFFF;
    for (unsigned int i = 0; i < 16; i++) { // Feistel rounds
        tmp = right;
        // Feistel function
        right = mangler_function(right, keys[i]);
        right ^= left;
        left = tmp;
    }
    block = (right << 32) | left;
    block = permute(block, fp, sizeof(fp));
    if (iv)
        *iv = block;
    block = htobe64(block); // Put block back to big endian
    return (block);
}

static int des_encode(t_ctx *ctx) {
    u_int64_t keys[16];
    u_int64_t block;
    u_int64_t *iv =
        ctx->opts.enc_mode != ENC_MODE_ECB ? &ctx->opts.iv.value : NULL;

    generate_keys(keys, ctx->opts.key.value, MODE_ENCODE);
    while (ctx->remaining >= 8) {
        ft_memcpy(&block, ctx->cursor, 8);
        block = des_encode_decode_block(block, keys, iv);
        if (write(ctx->fd_out, &block, 8) < 0) {
            ft_sdprintf(1, "%s: des: writing to file: %s\n", executable_name,
                        strerror(errno));
            return (1);
        }
        ctx->remaining -= 8;
        ctx->cursor += 8;
    }
    ft_memset(&block, (char)(8 - ctx->remaining), 8); // Padd
    ft_memcpy(&block, ctx->cursor, ctx->remaining);
    block = des_encode_decode_block(block, keys, iv);
    if (write(ctx->fd_out, &block, 8) < 0) {
        ft_sdprintf(1, "%s: des: writing to file: %s\n", executable_name,
                    strerror(errno));
        return (1);
    }
    return (0);
}

static int des_decode(t_ctx *ctx) {
    u_int64_t keys[16];
    u_int64_t block;
    u_int64_t *iv =
        ctx->opts.enc_mode != ENC_MODE_ECB ? &ctx->opts.iv.value : NULL;

    generate_keys(keys, ctx->opts.key.value, MODE_DECODE);
    while (ctx->remaining > 0) {
        ft_memcpy(&block, ctx->cursor, 8);
        block = des_encode_decode_block(block, keys, iv);
        if (ctx->remaining <= 8) // Dont print last block because of padding
            break;
        if (write(ctx->fd_out, &block, 8) < 0) {
            ft_sdprintf(1, "%s: des: writing to file: %s\n", executable_name,
                        strerror(errno));
            return (1);
        }
        ctx->remaining -= 8;
        ctx->cursor += 8;
    }
    char padlen = ((char *)&block)[7];
    if (padlen > 8) {
        ft_sdprintf(1, "%s: des: invalid padding len of %u\n", executable_name,
                    (unsigned int)padlen);
        return (1);
    }
    if (write(ctx->fd_out, &block, 8 - padlen) < 0) {
        ft_sdprintf(1, "%s: des: writing to file: %s\n", executable_name,
                    strerror(errno));
        return (1);
    }
    return (0);
}

static int write_salt(int fd, u_int64_t salt) {
    char buff[16] = "Salted__";

    salt = htobe64(salt);
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
    *salt = htobe64(*salt);
    return (0);
}

static int derive_key(t_ctx *ctx) {
    char dk[16];
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
        ft_sdprintf(1, "%s: des: %s: invalid hash option\n", executable_name,
                    ctx->opts.hash_option);
        return (1);
    }
    pbkdf1(&args);
    ctx->opts.key.value = htobe64(*(u_int64_t *)dk);
    if (ctx->opts.iv.given == false)
        ctx->opts.iv.value = htobe64(*(((u_int64_t *)dk) + 1));
    if (ctx->opts.print_key) {
        ft_sdprintf(1, "salt=%lX\nkey=%lX\n", ctx->opts.salt.value,
                    ctx->opts.key.value);
        if (ctx->opts.enc_mode != ENC_MODE_ECB)
            ft_sdprintf(1, "IV=%lX\n", ctx->opts.iv.value);
    }
    return (0);
}

int des(unsigned int nbr_arg, char **args, enum e_encryption_mode mode) {
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
    if (context.opts.mode == MODE_ENCODE)
        ret = des_encode(&context);
    else
        ret = des_decode(&context);
    free_ctx(&context);
    return (ret);
}

int des_ecb(unsigned int nbr_arg, char **args) {
    return (des(nbr_arg, args, ENC_MODE_ECB));
}

int des_cbc(unsigned int nbr_arg, char **args) {
    return (des(nbr_arg, args, ENC_MODE_CBC));
}
