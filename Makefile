ifdef __EA64__
SWITCH64=-D__EA64__
endif
SDKPATH=REPLACE_WITH_SDK_PATH
LIBIDAPATH=REPLACE_WITH_IDALIB_PATH
SRC=dalvikplugin.cpp
OBJS=dalvikplugin.o
PLUGIN=dalvikplugin.pmc
CC=g++
LD=g++
CFLAGS=-arch i386 -D__IDP__ -D__PLUGIN__ -c -D__MAC__ $(SWITCH64) -I$(SDKPATH)/include $(SRC)
LDFLAGS=-arch i386 --shared $(OBJS) -L$(SDKPATH) -L$(SDKPATH)/bin -L$(LIBIDAPATH) -lida --no-undefined -Wl

all:
	$(CC) $(CFLAGS)
	$(LD) $(LDFLAGS) -o $(PLUGIN)

clean:
	rm $(OBJS)