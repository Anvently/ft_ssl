#include <ft_openssl.h>
#include <sys/time.h>

u_int32_t left_rotate32(u_int32_t n, u_int8_t off) {
    return ((n << off) | (n >> (32 - off)));
}

u_int32_t right_rotate32(u_int32_t n, u_int8_t off) {
    return ((n >> off) | (n << (32 - off)));
}

u_int32_t right_rotate28(u_int32_t n, u_int8_t off) {
    return (((n >> off) | ((n << (28 - off)))) & 0xFFFFFFF);
}

u_int64_t left_rotate64(u_int64_t n, u_int8_t off) {
    return ((n << off) | (n >> (64 - off)));
}

u_int32_t left_rotate28(u_int32_t n, u_int8_t off) {
    return (((n << off) | ((n >> (28 - off)))) & 0xFFFFFFF);
}

u_int64_t right_rotate64(u_int64_t n, u_int8_t off) {
    return ((n >> off) | (n << (64 - off)));
}

u_int64_t random_u64(void) {
    u_int64_t n = 0;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    srand(tv.tv_usec);
    for (u_int8_t i = 0; i < 16; i++) {
        n |= (random() % 0xF);
        n <<= 4;
    }
    return (n);
}

u_int64_t permute(u_int64_t n, const u_int8_t *pt, u_int8_t pt_size) {
    u_int64_t new_n = 0;

    for (u_int8_t i = 0; i < pt_size; i++) {
        if (n & ((u_int64_t)1 << (63 - (pt[i] - 1))))
            new_n |= ((u_int64_t)1 << (63 - i));
    }
    return (new_n);
}

void print_bits(char *data, unsigned int size, bool newline) {
    unsigned int i = size;

    while (i--) {
        for (unsigned int j = 0; j < 8; j++) {
            ft_putchar_fd(data[i] & (1 << (7 - j)) ? '1' : '0', 1);
        }
        ft_putchar_fd(' ', 1);
    }
    if (newline)
        ft_putchar_fd('\n', 1);
    else
        fflush(stdout);
}