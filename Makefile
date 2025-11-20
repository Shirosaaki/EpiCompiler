# ==============================================
#                 Makefile
#  makefile
#  Author: shirosaaki
#  Date: 2025-11-20
# =============================================

SRC	=	$(wildcard src/*.c)

OBJ	=	$(SRC:.c=.o)

NAME	=	EpiCompiler

all: $(OBJ)
	gcc -o $(NAME) $(OBJ)

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(NAME)

re: fclean all
