#include <libft.h>

#define REVERT_ENDIANESS_32(n)                                                 \
    ((((u_int8_t *)&(n))[0] << 24) | (((u_int8_t *)&(n))[1] << 16) |           \
     (((u_int8_t *)&(n))[2] << 8) | (((u_int8_t *)&(n))[3] << 0))

int read_file(int fd, char **vec);
u_int32_t left_rotate(u_int32_t n, u_int8_t off);
u_int32_t right_rotate(u_int32_t n, u_int8_t off);