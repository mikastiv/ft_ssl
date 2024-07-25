NAME = ft_ssl

CC = clang
CFLAGS = -Wall -Wextra -Werror -Wpedantic -Wshadow -fno-strict-aliasing

SRCDIR = src
OBJDIR = obj
CFILES = main.c utils.c md5.c sha2.c digest.c whirlpool.c base64.c parse.c des.c pbkdf2.c cipher.c arena.c rsa.c bignum.c asn1.c
HFILES = types.h utils.h ssl.h parse.h cipher.h digest.h globals.h arena.h standard.h bignum.h asn1.h
SRC = $(addprefix $(SRCDIR)/, $(CFILES))
INC = $(addprefix $(SRCDIR)/, $(HFILES))
OBJ = $(addprefix $(OBJDIR)/, $(CFILES:.c=.o))

OS := $(shell uname)
ifeq ($(OS), Darwin)
LIB =
else
LIB = -lbsd
endif

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -I$(SRCDIR) -c $< -o $@

all: $(NAME)

$(NAME): $(OBJDIR) $(OBJ)
	$(CC) $(OBJ) $(LIB) -o $(NAME)

$(OBJDIR):
	mkdir -p $(OBJDIR)

debug: CFLAGS += -g
debug: all

release: CFLAGS += -O3 -DNDEBUG
release: all

fmt:
	@clang-format -i $(SRC) $(INC)

clean:
	$(RM) $(OBJ)

fclean: clean
	$(RM) $(NAME) $(LINK)

re: fclean all

.PHONY: all clean fclean re release debug
