#include <ft_openssl.h>
#include <sys/time.h>

u_int32_t left_rotate(u_int32_t n, u_int8_t off) {
    return ((n << off) | (n >> (32 - off)));
}

u_int32_t right_rotate(u_int32_t n, u_int8_t off) {
    return ((n >> off) | (n << (32 - off)));
}

u_int64_t left_rotate64(u_int64_t n, u_int8_t off) {
    return ((n << off) | (n >> (64 - off)));
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