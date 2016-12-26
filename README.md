# Resign v2.0#

## Description ##

A burp extender that recalculate signature value automatically after you modified request parameter value.but you need to know the signature algorithm detail and configure at GUI. 

一个可以在你修改请求参数值后，自动从新计算sign的burp插件。但是前提是你需要知道具体的算法细节，并且在插件的GUI中配置。

![](http://i.imgur.com/4YQR4IT.png)

## Background ##

 More and more mobile developers begin to use the signature algorithm to improve the security of App. when we test the App generated requests, always need to recalculate the sign value and update it again and again to make the request pass the server check.

越来越多的移动开发者在App的请求中加入签名来提高安全性。当我们测试App生成的请求接口，总需要一次又一次地从新计算sign并更新sign值才能保证请求通过服务端的校验。

## Requirement ##

Java 1.8

## Usage ##

1. download this extender from [here](https://github.com/bit4woo/GUI_Burp_Extender_ReSign/releases "here") , and add to burp.


2. Use "Send to ReSign"![](http://i.imgur.com/kbThsZJ.png)


3. Chose take effect for. you can control which components take effect for by select or cancel the select on the Window top


4. Config


first, which parameters will take part in and how to sort. remove the ones that don't need, move up and down or click table header to sort.

第一，决定哪些参数要参与签名，将不需要的参数移除；决定参数如何排序，可以通过“move up”和“move down”来自定义排序，也可以通过点击表头来实现升序降序排序。

second, which parameter is sign. select the sign parameter and click "Mark As Sign".

第二，标记出签名字段，选择签名的字段，并点击“Mark As Sign”将其标记为sign字段。
	
thirdly, input the secrect key(md5 salt).if secret key will be use as a normal parameter, it should be like "key=secretkey" --a key value format;if the secret key will be append to the end when parameters have been oredered and combined, should be like "&key=secretkey"(there is a connector string usually, & is the connector string in this example.) 

第三，输入secret key（或者md5盐）。如果这个key将被当作和普通参数一样对待，那么它的格式应该是键值对的形式。如果key是在参数排好序、拼接好后附加在末尾，那么它应该包含一个连接符（如果需要的话）比如“&key=secretkey”。

finally, chose how to combine parameters.

最后，决定怎样拼接参数。是否值使用value，不需要“key=”； 拼接是否需要使用连接字符，连接字符是什么（一般是&）

**Caution:you can always click "show final string" to see whether the result string is you want.**

**重要提示：如果对选项理解不清晰，你可以随时点击“show final string”看看拼接的效果。**


5.Use timestamp in parameter

![](http://i.imgur.com/r0NDPv1.jpg)


## ReSign v2.0 Change log ##


- support SHA1.
- support custome order.
- support parameter combine control: chose whether only use value; specify the connector string.
- adjust the scope policy that the extender config take effect:this extender is main for single request(like other burp origin components)，that means you need to config again for each request. if the config are same in same domain, you don't need to do that again.

- 增加SHA1算法支持。
- 增加自定义排序支持。
- 增加字符拼接控制：是否只使用value,指定拼接连接符。
- 调整插件生效范围策略：主要针对单个请求(就像burp的原生组件一样)，也就是说对于每个单独的请求都需从新配置。但是如果同域下其他接口的签名参数和方法完全一样，则可以不用重新配置。


## ReSign v2.1 Change log ##

- fix remove issue after sort.
- support remove multiple rows.
- fix URL encode issue in "Send to ReSign" menu.

- 修复排序后删除异常的问题。
- 增加支持多行删除。
- 修复“发送到 Resign”中的URL编码问题。


## ReSign v2.2 Change log ##

- Support timestamp in parameter value ,basing on current system time.
- Optimized log format.


- 支持时间戳形式的参数值，通过获取当前系统时间实现。
- 优化了log输出格式。


## issue and contribute ##

any issue and contribute are welcomed。

欢迎提issue，提bug。