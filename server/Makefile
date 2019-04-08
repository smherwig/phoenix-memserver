INCLUDES=$(HOME)/include
STATIC_LIBS= $(addprefix $(HOME)/lib/, librpc.a librho.a)

#CPPFLAGS= -I $(INCLUDES) -DRHO_DEBUG -DRHO_TRACE
CPPFLAGS= -I $(INCLUDES)
CFLAGS= -Wall -Werror -Wextra
LDFLAGS= $(STATIC_LIBS) -lssl -lcrypto -lpthread

OBJS = \
	   mdishserver.o

mdishserver: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

mdishserver.o: mdishserver.c mdish.h

clean:
	rm -f mdishserver $(OBJS)

.PHONY: clean
