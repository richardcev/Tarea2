EXEC = encrypter
INCL = headers/
LIBS = libs/

all: $(EXEC)

$(EXEC): $(LIBS)sha256.o $(LIBS)aes.o $(LIBS)blowfish.o $(EXEC).o
	gcc $(DFLAGS) -Wall -o $@ $(LIBS)sha256.o $(LIBS)aes.o $(LIBS)blowfish.o $(EXEC).o

$(LIBS)%.o: $(LIBS)%.c $(INCL)%.h
	gcc $(DFLAGS) -Wall -c -o $@ $< -iquote $(INCL)

%.o: %.c $(INCL)sha256.h $(INCL)aes.h $(INCL)blowfish.h
	gcc $(DFLAGS) -Wall -c -o $@ $< -iquote $(INCL)

# Compila usando la opción -g para facilitar la depuración con gdb.
debug: DFLAGS = -g
debug: clean $(EXEC)

# Compila habilitando la herramienta AddressSanitizer para
# facilitar la depuración en tiempo de ejecución.
sanitize: DFLAGS = -fsanitize=address,undefined
sanitize: clean $(EXEC)

.PHONY: all clean sanitize debug 
clean:
	rm -rf $(EXEC) $(EXEC).o $(LIBS)*.o

