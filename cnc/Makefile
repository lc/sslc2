NAME=cnc

all: cnc

clean:
	rm -rf cnc cnc.o

cnc: cnc.asm
	nasm -f elf -F dwarf -g cnc.asm
	gcc -g -m32 -o cnc cnc.o asm_io.o
