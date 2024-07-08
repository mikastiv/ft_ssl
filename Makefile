NAME = ft_ssl

CC = clang
CFLAGS = -Wall -Wextra -Werror -Wpedantic -Wshadow -fno-strict-aliasing

SRCDIR = src
OBJDIR = obj
CFILES = main.c utils.c md5.c sha2.c digest.c whirlpool.c base64.c parse.c des.c pbkdf2.c cipher.c
HFILES = types.h utils.h ssl.h parse.h cipher.h digest.h globals.h
SRC = $(addprefix $(SRCDIR)/, $(CFILES))
INC = $(addprefix $(SRCDIR)/, $(HFILES))
OBJ = $(addprefix $(OBJDIR)/, $(CFILES:.c=.o))

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -I$(SRCDIR) -c $< -o $@

all: $(NAME)

$(NAME): $(OBJDIR) $(OBJ)
	$(CC) $(OBJ) -lbsd -o $(NAME)

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
