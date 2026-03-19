/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_split.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: npirard <npirard@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/11/07 18:15:11 by npirard           #+#    #+#             */
/*   Updated: 2024/01/11 10:51:10 by npirard          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

static int count_words(char const *s, int (*fun)(char)) {
    int i;
    int j;
    int count;

    i = 0;
    count = 0;
    while (s[i]) {
        while (s[i] && fun(s[i]))
            i++;
        j = 0;
        while (s[i + j] && fun(s[i + j]) == 0)
            j++;
        if (j)
            count++;
        i += j;
    }
    return (count);
}

static char **parse_words(char const *s, char **strings, int (*fun)(char)) {
    int i;
    int j;
    int word_index;

    i = 0;
    word_index = 0;
    while (s[i]) {
        while (s[i] && fun(s[i]))
            i++;
        j = 0;
        while (s[i + j] && fun(s[i + j]) == 0)
            j++;
        if (j) {
            word_index++;
            strings[word_index - 1] = ft_substr(s, i, j);
            if (!strings[word_index - 1])
                return (ft_free_strs(strings));
        }
        i += j;
    }
    return (strings);
}

/// @brief Return a list of allocated string for each substring
/// found in s using c as a delimiter. The list is null terminated.
/// @param s string to split using the delimiter
/// @param fun function returning 1 if char is a delimiter
/// @return Address of a null terminated list of string.
/// NULL if allocation fails.
char **ft_split_fun(char const *s, int (*fun)(char)) {
    char **strings;
    size_t nb_words;

    if (!s)
        return (NULL);
    nb_words = count_words(s, fun);
    strings = malloc((nb_words + 1) * sizeof(char *));
    if (!strings)
        return (NULL);
    strings[nb_words] = NULL;
    if (!parse_words(s, strings, fun))
        return (NULL);
    return (strings);
}
