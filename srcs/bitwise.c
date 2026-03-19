#include <ft_openssl.h>

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