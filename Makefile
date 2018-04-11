flags=-Wall
libs=-lncurses

emu: emu.o alienos_syscall.o
	gcc ${flags} -o $@ $^ ${libs}

emu.o: emu.c alienos_syscall.h alienos.h
	gcc ${flags} -c -o $@ emu.c

alienos_syscall.o: alienos_syscall.c alienos_syscall.h alienos.h
	gcc ${flags} -c -o $@ alienos_syscall.c

clean:
	rm *.o emu
