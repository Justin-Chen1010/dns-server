CC=gcc
OBJ=packet_parser.o
COPT=-Wall -Wpedantic -g
BIN_PHASE1=phase1
BIN_PHASE2=dns_svr

all: $(BIN_PHASE1) $(BIN_PHASE2)

$(BIN_PHASE2): main.c $(OBJ)
	$(CC) -o $(BIN_PHASE2) main.c $(OBJ) $(COPT)

$(BIN_PHASE1): phase1.c $(OBJ)
	$(CC) -o $(BIN_PHASE1) phase1.c $(OBJ) $(COPT)

%.o: %.c %.h
	$(CC) -c $< $(COPT) -g

format:
	clang-format -i *.c *.h

clean:
	rm -f *.o *.exe $(BIN_PHASE1) $(BIN_PHASE2)

