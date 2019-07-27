INCLUDES=$(HOME)/include
STATIC_LIBS= $(addprefix $(HOME)/lib/, librpc.a librho.a)

CPPFLAGS= -I $(INCLUDES)
#CPPFLAGS= -I $(INCLUDES) -DRHO_DEBUG -DRHO_TRACE
CFLAGS= -Wall -Werror -Wextra
LDFLAGS= $(STATIC_LIBS) -lssl -lcrypto -lpthread

OBJS = \
	   smdishserver.o

smdishserver: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

smdishserver.o: smdishserver.c smdish.h

clean:
	rm -f smdishserver $(OBJS)

.PHONY: clean
