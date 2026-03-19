NAME		=	ft_ssl

INCLUDES	=	includes/
SRCS_FOLDER	=	srcs/
OBJS_FOLDER	=	.objs/

SRCS_FILES	=	main.c parse_args_md5.c md5.c sha256.c file.c interactive_mode.c

OBJS		=	$(addprefix $(OBJS_FOLDER),$(SRCS_FILES:.c=.o))
SRCS		=	$(addprefix $(SRCS_FOLDER),$(SRCS_FILES))

LIBFT		=	libft/libft.a

CC			=	gcc
CFLAGS		=	-Wall -Wextra -Werror -g3 -I$(INCLUDES) -Ilibft/ -D_GNU_SOURCE -fsanitize=address

.PHONY		=	all clean fclean re

all: $(NAME)

$(NAME): $(LIBFT) $(OBJS) Makefile
	@echo "\n-----COMPILING $(NAME)-------\n"
	$(CC) $(CFLAGS) $(OBJS) -o $(NAME) -Llibft/ -lft
	@echo "Executable has been successfully created."


$(OBJS_FOLDER)%.o: $(SRCS_FOLDER)%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIBFT):
	@echo "\n-------COMPILING LIBFT--------------\n"
	make -C libft/
	make clean -C libft/
	@echo "\n\n"

clean:
	@echo "\n-------------CLEAN--------------\n"
	make clean -C libft/
	rm -rf $(OBJS_FOLDER)
	@echo "object files have been removed."

fclean: clean
	@echo "\n-------------FORCE CLEAN--------------\n"
	make fclean -C libft/
	rm -rf $(NAME)
	@echo "$(NAME) and object files have been removed."

re: fclean all

