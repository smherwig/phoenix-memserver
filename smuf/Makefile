INCLUDES=$(HOME)/include
STATIC_LIBS= $(addprefix $(HOME)/lib/, librpc.a librho.a)

CPPFLAGS= -I $(INCLUDES)
#CPPFLAGS= -I $(INCLUDES) -DRHO_DEBUG -DRHO_TRACE
CFLAGS= -Wall -Werror -Wextra
LDFLAGS= $(STATIC_LIBS) -lssl -lcrypto -lpthread

OBJS = \
	   smufserver.o

smufserver: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

smufserver.o: smufserver.c smuf.h

clean:
	rm -f smufserver $(OBJS)

.PHONY: clean
