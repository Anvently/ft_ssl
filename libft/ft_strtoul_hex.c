#include <libft.h>
#include <limits.h>

static int increment_nbr(unsigned long *dest, int index, size_t len_base) {
    if (*dest > ULONG_MAX / len_base)
        return (1);
    if (*dest == ULONG_MAX / len_base) {
        if ((size_t)index > ULONG_MAX % len_base)
            return (1);
    }
    *dest = *dest * len_base + index;
    return (0);
}

static int base_index(char c) {
    static const char base[] = "0123456789abcdef";
    int index = 0;

    while (index < 16) {
        if (ft_tolower(c) == base[index])
            return (index);
        index++;
    }
    return (-1);
}

/// @brief Convert the initial part of a string written in hexa to an unsigned
/// long integer. Format : \\[n spaces\\][n base-digit] Check for overflow.
/// @param str String to convert
/// @param dest int receiving the conversion.
/// @param ptr Optional parameter which will pointed to the end of the parsed
/// sequence. The full sequence is parsed even in case of errors.
/// @return ```0``` if no error occured. ```1``` if overflow.
/// ```2``` if format error
int ft_strtoul_hex(const char *str, unsigned long *dest, const char **ptr) {
    const size_t len_base = 16;
    int index;
    // size_t			i;

    // i = 0;
    *dest = 0;
    if (ptr == NULL)
        ptr = &str;
    while (ft_isspace(**ptr))
        (*ptr)++;
    index = base_index(**ptr);
    if (index < 0)
        return (2);
    while (**ptr && (index = base_index(**ptr)) >= 0) {
        if (increment_nbr(dest, index, len_base))
            return (1);
        (*ptr)++;
    }
    if (**ptr && ft_isspace(**ptr) == false)
        return (2);
    return (0);
}