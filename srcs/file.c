#include <ft_openssl_utils.h>

int read_file(int fd, char **vec) {
    ssize_t nread;
    size_t size = 0;
    size_t capacity = 1024;

    *vec = ft_vector_create(sizeof(char), capacity);
    if (*vec == NULL)
        return (1);
    size = nread = read(fd, *vec + size, capacity - 1);
    while (nread > 0) {
        if (size == (capacity - 1)) {
            capacity *= 2;
            if (ft_vector_reserve((t_vector **)vec, capacity)) {
                ft_vector_free((t_vector **)vec);
                return (1);
            }
        }
        nread = read(fd, *vec + size, capacity - (size + 1));
        size += nread;
    }
    if (nread < 0) {
        ft_vector_free((t_vector **)vec);
        return (1);
    }
    (*vec)[size] = '\0';
    ft_vector_resize((t_vector **)vec, size + 1);
    return (0);
}
