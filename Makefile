NAME = ft_ssl

CC = clang
CFLAGS = -Wall -Wextra -Werror -Wpedantic -Wshadow -fno-strict-aliasing

SRCDIR = src
OBJDIR = obj
CFILES = main.c utils.c md5.c sha2.c
HFILES = types.h utils.h ssl.h
SRC = $(addprefix $(SRCDIR)/, $(CFILES))
INC = $(addprefix $(SRCDIR)/, $(HFILES))
OBJ = $(addprefix $(OBJDIR)/, $(CFILES:.c=.o))

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -I$(SRCDIR) -c $< -o $@

all: $(NAME)

$(NAME): $(OBJDIR) $(OBJ)
	$(CC) $(OBJ) -lm -o $(NAME)

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
