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

static void parse_words(char *s, char **strings, int (*fun)(char)) {
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
            strings[word_index++] = s + i;
            s[i + j] = '\0';
            j++;
        }
        i += j;
    }
}

/// @brief Return an allocated list of string for each substring
/// found in s using c as a delimiter. The list is null terminated.
/// The strings itself is NOT allocated and the first splitting character are
/// replaced with ```NULL``` bytes.
/// @param s string to split using the delimiter. Modified and used by the
/// returned array.
/// @param fun function returning 1 if char is a delimiter
/// @return Address of a null terminated list of string.
/// NULL if allocation fails.
char **ft_split_static(char *s, int (*fun)(char)) {
    char **strings;
    size_t nb_words;

    if (!s)
        return (NULL);
    nb_words = count_words(s, fun);
    strings = malloc((nb_words + 1) * sizeof(char *));
    if (!strings)
        return (NULL);
    strings[nb_words] = NULL;
    parse_words(s, strings, fun);
    return (strings);
}
