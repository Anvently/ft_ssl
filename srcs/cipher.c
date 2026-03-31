#include <ft_cipher.h>

extern const char *executable_name;

static u_int64_t encrypt_block(struct s_cipher_context *ctx, u_int64_t block) {
    u_int64_t tmp;

    switch (ctx->enc_mode) {
    case ENC_MODE_ECB:
        return (ctx->encrypt_fun(block, ctx->data));

    case ENC_MODE_CBC:
        block ^= ctx->iv;
        block = ctx->encrypt_fun(block, ctx->data);
        ctx->iv = block;
        return (block);

    case ENC_MODE_PCBC:
        tmp = block;
        block ^= ctx->iv;
        block = ctx->encrypt_fun(block, ctx->data);
        ctx->iv = tmp ^ block;
        return (block);

    case ENC_MODE_CFB:

    default:
        error(1, 0, "Unsupported mode of encryption\n");
    }
    return (0);
}

static u_int64_t decrypt_block(struct s_cipher_context *ctx, u_int64_t block) {
    u_int64_t tmp;

    switch (ctx->enc_mode) {
    case ENC_MODE_ECB:
        return (ctx->decrypt_fun(block, ctx->data));

    case ENC_MODE_CBC:
        tmp = ctx->iv;   // BE to LE
        ctx->iv = block; // LE to BE
        block = ctx->decrypt_fun(block, ctx->data);
        block ^= tmp;
        return (block);

    case ENC_MODE_PCBC:
        tmp = block; // tmp is LE
        block = ctx->decrypt_fun(block, ctx->data);
        block ^= ctx->iv;      // IV: BE -> LE
        ctx->iv = tmp ^ block; // Store IV as BE
        return (block);

    case ENC_MODE_CFB:

    default:
        error(1, 0, "Unsupported mode of encryption\n");
    }
    return (0);
}

int cipher_encrypt(struct s_cipher_context *ctx) {
    u_int64_t block;

    while (ctx->remaining >= 8) {
        ft_memcpy(&block, ctx->payload, 8);
        block = encrypt_block(ctx, block);
        if (write(ctx->fd_out, &block, 8) < 0) {
            ft_sdprintf(1, "%s: %s: writing to file: %s\n", executable_name,
                        ctx->name, strerror(errno));
            return (1);
        }
        ctx->remaining -= 8;
        ctx->payload += 8;
    }
    if (ctx->padlen) {
        ft_memset(&block, (char)(8 - ctx->remaining), 8); // Padd
    } else {
        ft_memset(&block, 0, 8); // Padd with 0
    }
    ft_memcpy(&block, ctx->payload, ctx->remaining);
    block = encrypt_block(ctx, block);
    if (write(ctx->fd_out, &block, ctx->padlen ? ctx->padlen : ctx->remaining) <
        0) {
        ft_sdprintf(1, "%s: %s: writing to file: %s\n", executable_name,
                    ctx->name, strerror(errno));
        return (1);
    }
    return (0);
}

int cipher_decrypt(struct s_cipher_context *ctx) {
    u_int64_t block;
    u_int8_t padlen;

    while (ctx->remaining > 0) {
        ft_memcpy(&block, ctx->payload, 8);
        block = decrypt_block(ctx, block);
        if (ctx->remaining <= 8) // Dont print last block because of padding
            break;
        if (write(ctx->fd_out, &block, 8) < 0) {
            ft_sdprintf(1, "%s: %s: writing to file: %s\n", executable_name,
                        ctx->name, strerror(errno));
            return (1);
        }
        ctx->remaining -= 8;
        ctx->payload += 8;
    }
    if (ctx->padlen) { // If a specific padding is required
        padlen = ((char *)&block)[7];
        if (padlen > 8) {
            ft_sdprintf(1, "%s: %s: invalid padding len of %u\n",
                        executable_name, ctx->name, (unsigned int)padlen);
            return (1);
        }
    }
    if (write(ctx->fd_out, &block, ctx->padlen ? 8U - padlen : ctx->remaining) <
        0) {
        ft_sdprintf(1, "%s: %s: writing to file: %s\n", executable_name,
                    ctx->name, strerror(errno));
        return (1);
    }
    return (0);
}