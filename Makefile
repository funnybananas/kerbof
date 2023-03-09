BOFNAME := KerBOF
CC_x64 := x86_64-w64-mingw32-gcc
STRIP := strip
OPTIONS := -masm=intel -Wall -I include

bof: bof_64

bof_64:
	$(CC_x64) -c src/entry.c -o dist/$(BOFNAME).x64.o -DBOF $(OPTIONS)
	$(STRIP) --strip-unneeded dist/$(BOFNAME).x64.o
