#ifndef FT_OPENSSL_UTILS_H
#define FT_OPENSSL_UTILS_H
#include <libft.h>

#define REVERT_ENDIANESS_32(n)                                                 \
    (((u_int32_t)((u_int8_t *)&(n))[0] << 24) |                                \
     ((u_int32_t)((u_int8_t *)&(n))[1] << 16) |                                \
     ((u_int32_t)((u_int8_t *)&(n))[2] << 8) |                                 \
     ((u_int32_t)((u_int8_t *)&(n))[3] << 0))

#define REVERT_ENDIANESS_64(n)                                                 \
    (((u_int64_t)((u_int8_t *)&(n))[0] << 56) |                                \
     ((u_int64_t)((u_int8_t *)&(n))[1] << 48) |                                \
     ((u_int64_t)((u_int8_t *)&(n))[2] << 40) |                                \
     ((u_int64_t)((u_int8_t *)&(n))[3] << 32) |                                \
     ((u_int64_t)((u_int8_t *)&(n))[4] << 24) |                                \
     ((u_int64_t)((u_int8_t *)&(n))[5] << 16) |                                \
     ((u_int64_t)((u_int8_t *)&(n))[6] << 8) |                                 \
     ((u_int64_t)((u_int8_t *)&(n))[7] << 0))

int read_file(int fd, char **vec);
u_int32_t left_rotate32(u_int32_t n, u_int8_t off);
u_int32_t right_rotate32(u_int32_t n, u_int8_t off);

u_int64_t left_rotate64(u_int64_t n, u_int8_t off);
u_int64_t right_rotate64(u_int64_t n, u_int8_t off);

u_int32_t left_rotate28(u_int32_t n, u_int8_t off);
u_int32_t right_rotate28(u_int32_t n, u_int8_t off);

u_int64_t permute(u_int64_t n, const u_int8_t *pt, u_int8_t pt_size);

int print_character_64(int fd, const char *buff, unsigned int n);
void print_bits(char *data, unsigned int size, bool newline);

u_int64_t random_u64(void);

#endif