CC = g++
CFLAGS = -O3 -Wall
LIBS = -lcrypto -lssl -lpthread -lsnappy 
INCLUDES = -I./lib/leveldb-1.15.0/include -I./backend/ -I./utils/ -I./lib/cryptopp -I./comm/ -I./dedup/ 
JERASURE_OBJS = 
MAIN_OBJS = ./utils/CryptoPrimitive.o ./dedup/DedupCore.o ./backend/BackendStorer.o ./comm/server.o

all: leveldb server

leveldb:
	make -C ./lib/leveldb-1.15.0

%.o: %.cc %.hh
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

server: main.cc $(MAIN_OBJS)  
	$(CC) $(CFLAGS) $(INCLUDES) -o SERVER main.cc $(MAIN_OBJS) ./lib/leveldb-1.15.0/libleveldb.a $(LIBS)

clean:
	@rm -f SERVER
	@rm -f $(MAIN_OBJS)
