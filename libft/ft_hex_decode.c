#include <libft.h>

static const char hexa_base[] = "0123456789abcdef";

/// @brief Decode an hexadecimal string to an output buffer
/// @param str hexadecimal string
/// @param out output buffer. Can be equal to ```str```
/// @param out_size value result parameter containing the size of out buffer
/// @return ```0``` for success. ```1``` for format error. ```2``` for overflow
/// error. ```3``` for invalid argument.
int ft_hex_decode(const char *str, u_int8_t *out, size_t *out_size) {
    size_t size = 0;

    if (out == NULL || out_size == NULL)
        return (3);
    while (*str && size < out_size) {

        size++;
        str++;
    }
    *out_size = size;
    if (*str) // overflow
        return (2);
    return (0);
}