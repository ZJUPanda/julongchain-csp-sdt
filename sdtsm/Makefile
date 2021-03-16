CC = gcc
OPT = -O2
TGT = test
OBJ = SM3.o SM2.o test.o

all: $(TGT) $(APP)

$(OBJ): %o:%c
	$(CC) -c $? -o $@

$(TGT):$(OBJ) 
	$(CC) -o $(TGT) $(OBJ) $(OPT)
	
clean:
	rm -rf *.o *.bak $(TGT) $(APP)