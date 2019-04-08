@ECHO OFF
gcc -m32 -ffreestanding  -c crypter_c.c -o crypter_c.o
ld -mi386pe -o crypter_c.tmp -Tlinker.ld 
objcopy -O binary crypter_c.tmp crypter_c.bin
python -c "r = file('crypter_c.bin','rb').read();w = file('crypter_c.bin','wb');w.write(r[:0x512]);"