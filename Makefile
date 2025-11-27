# ==============================================
#                 Makefile
#  makefile
#  Author: shirosaaki
#  Date: 2025-11-20
# =============================================

SRC	=	$(wildcard src/*.c)

OBJ	=	$(SRC:.c=.o)

NAME	=	EpiCompiler

CFLAGS	=	-Wall -Wextra -g

all: $(OBJ)
	gcc $(CFLAGS) -o $(NAME) $(OBJ)

%.o: %.c
	gcc $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
