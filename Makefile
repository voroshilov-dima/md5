NAME			 = ft_ssl

CC 				 = gcc
CCFLAGS			 = -Wall -Werror -Wextra -pthread
SRC_FILES		 =	main.c				\
					md5_init.c			\
					md5_support.c		\
					md5_calculations.c

SRC_DIR			 = srcs/
OBJ_DIR			 = obj/
OBJ_FILES		 = $(SRC_FILES:.c=.o)
SRC				 = $(addprefix $(SRC_DIR), $(SRC_FILES))
OBJ				 = $(addprefix $(OBJ_DIR), $(OBJ_FILES))

LIBFT_FILE		 = libft.a
LIBFT_DIR		 = libft/
LIBFT_FLAGS		 = -lft -L $(LIBFT_DIR)
LIBFT			 = $(addprefix $(LIBFT_DIR), $(LIBFT_FILE))
INC 			 = includes/

FLAGS			 = $(CCFLAGS) $(LIBFT_FLAGS)

FT_SSL_HEADER = ft_ssl.h

all: $(NAME)

$(NAME): $(LIBFT) $(OBJ)
	$(CC) -o $(NAME) $(OBJ) $(LIBFT_DIR)*.o

$(OBJ_DIR)%.o: $(SRC_DIR)%.c $(INC)$(FT_SSL_HEADER)
	$(CC) $(CCFLAGS) -I $(INC) -I $(LIBFT_DIR) -c $< -o $@ 

$(OBJ): | $(OBJ_DIR)

$(OBJ_DIR):
	mkdir $(OBJ_DIR)

$(LIBFT):
	make -C $(LIBFT_DIR)

clean:
	rm -rf $(OBJ_DIR)
	make clean -C $(LIBFT_DIR)

fclean: clean
	rm -f $(NAME)
	make fclean -C $(LIBFT_DIR)

re: fclean all
