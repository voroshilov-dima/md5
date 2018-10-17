# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: dvoroshy <marvin@42.fr>                    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2016/11/28 11:01:02 by dvoroshy          #+#    #+#              #
#    Updated: 2016/12/06 17:35:47 by dvoroshy         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = libft.a
SRC = ft_memset.c			\
	  ft_bzero.c			\
	  ft_memcpy.c			\
	  ft_memccpy.c			\
	  ft_memmove.c			\
	  ft_memchr.c			\
	  ft_memcmp.c			\
	  ft_strlen.c			\
	  ft_strdup.c			\
	  ft_strcpy.c			\
	  ft_strncpy.c			\
	  ft_strcat.c			\
	  ft_strncat.c			\
	  ft_strchr.c			\
	  ft_strlcat.c  		\
	  ft_strrchr.c  		\
	  ft_strstr.c			\
	  ft_strnstr.c			\
	  ft_strcmp.c			\
	  ft_strncmp.c			\
	  ft_atoi.c				\
	  ft_isalpha.c			\
	  ft_isdigit.c			\
	  ft_isalnum.c			\
	  ft_isascii.c			\
	  ft_isprint.c			\
	  ft_toupper.c			\
	  ft_tolower.c			\
	  ft_memalloc.c			\
	  ft_memdel.c			\
	  ft_strnew.c			\
	  ft_strdel.c			\
	  ft_strclr.c			\
	  ft_striter.c			\
	  ft_striteri.c			\
	  ft_strmap.c			\
	  ft_strmapi.c			\
	  ft_strequ.c			\
	  ft_strnequ.c			\
	  ft_strsub.c			\
	  ft_strjoin.c			\
	  ft_strtrim.c			\
	  ft_strsplit.c			\
	  ft_itoa.c				\
	  ft_putchar.c			\
	  ft_putstr.c			\
	  ft_putendl.c			\
	  ft_putnbr.c			\
	  ft_putchar_fd.c		\
	  ft_putstr_fd.c		\
	  ft_putendl_fd.c		\
	  ft_putnbr_fd.c		\
	  ft_lstnew.c			\
	  ft_lstdelone.c		\
	  ft_lstdel.c			\
	  ft_lstadd.c			\
	  ft_lstiter.c			\
	  ft_lstmap.c			\
	  ft_strsplit_lst.c		\
	  ft_strswap.c			\
	  ft_list_find.c		\
	  ft_list_foreach_if.c	\
	  ft_list_reverse.c		\
	  ft_printf/main.c		\
	  ft_printf/parse_format.c		\
	  ft_printf/print_non_numbers.c		\
	  ft_printf/print_signed_numbers.c		\
	  ft_printf/print_unicode.c		\
	  ft_printf/print_unsigned_numbers.c		\
	  ft_printf/support_functions1.c		\
	  ft_printf/support_functions2.c		\
	  ft_printf/support_functions3.c		\



OBJ = $(SRC:.c=.o)
FLAGS = -Wall -Werror -Wextra

all: $(NAME) 

$(NAME): $(OBJ)
	ar rc libft.a $(OBJ)

%.o: %.c 
	gcc $(FLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(NAME) 

re: fclean all
