#include <libft.h>

static const char hexa_base[] = "0123456789ABCDEF";

int16_t ft_hex2bin(char c) {
    c = ft_toupper(c);
    for (u_int8_t i = 0; i < sizeof(hexa_base); i++) {
        if (c == hexa_base[i])
            return ((int16_t)i);
    }
    return (-1);
}

void ft_bin2hex(u_int8_t value, char out[2]) {
    out[0] = hexa_base[value >> 4];
    out[1] = hexa_base[value & 0xF];
}

/// @brief Decode an hexadecimal string to an output buffer
/// @param str hexadecimal string
/// @param out output buffer. Cannot be equal to ```str```
/// @param out_size value result parameter containing the size of out buffer
/// @param leftpad define padding behaviour for odd input. Exemple: abcdef ->
/// 0abcdef (```true```), abcdef0 (```false```).
/// @return ```0``` for success. ```1``` for format error. ```2``` for overflow
/// error. ```3``` for invalid argument.
int ft_hex_decode(const char *str, u_int8_t *out, size_t *out_size,
                  bool leftpad) {
    size_t size = 0;
    size_t len = ft_strlen(str);
    int16_t value;

    if (out == NULL || out_size == NULL)
        return (3);
    while (*str && size < *out_size) {
        if (size == 0 && leftpad && len % 2 == 1) {
            // ODD with left padding, padd first character
            value = ft_hex2bin(*str);
            if (value < 0)
                return (1);
            out[size++] = value;
            str++;
            continue;
        }
        if (*(str + 1) == 0 && leftpad == false) {
            // ODD with right padding, padd last character
            value = ft_hex2bin(*str);
            if (value < 0)
                return (1);
            out[size++] = value << 4;
            str++;
            break;
        }
        value = ft_hex2bin(*str);
        if (value == -1)
            return (1);
        out[size] = (u_int8_t)value << 4;
        value = ft_hex2bin(*(str + 1));
        if (value == -1)
            return (1);
        out[size] |= (u_int8_t)value;
        size++;
        str += 2;
    }
    *out_size = size;
    if (*str) // overflow
        return (2);
    return (0);
}