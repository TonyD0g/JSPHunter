# JSPHunter [Java 8] 蓝队工具

**基于污点分析和模拟栈帧技术的JSP Webshell检测**     `仅做学习记录`

我发现JSPFinder和JSPKiller模拟栈帧的部分几乎一致，因此不重复造轮子，直接在JSPFinder的基础上进行改进,所以 **85%** 代码来源于JSPFinder和JSPKiller,感激这两个作品的作者.   

尝试对其进行优化检测逻辑和重构,以作为自己学习污点分析和模拟栈帧技术的检验和毕业设计.

目前正在不断更新优化，**欢迎师傅们提交bypass**，我会进行优化改进

**测试环境：8.5.81**

**注意：对内存马没用！**

# 个人优化

(相比于 JSPFinder,JSPKiller)

- 使用jasper 编译(JSPFinder已经实现了)

- PassthroughDiscovery 类性能比gadgetinspector的高 (JSPFinder已经实现了)

- 将 FindEvilDiscovery 中的 visitMethodInsn 抽离出来,方便于扩展

- 增强检测能力: 检测能力比JSPFinder更强,检测正常jsp文件格式不会报错,能把"webshell bypass"的绕过全部检测出来

- 将污点源黑名单导出到一个文件中,使用fileUtils去读取,方便于扩展

# TODO

- //todo 解决继承,实现接口能导致绕过的问题
- 增加检测能力:   检测bypass文件夹下的jsp webshell
- 设置导出结果名单 -o 参数
- 将Evil方法导出为文件,便于修改和扩展

# webshell bypass

**1.https://github.com/threedr3am/JSP-WebShells**

三个污点分析工具的检测率:

- JSPKiler: 待测

- JSPFinder:  4/29 ,  13%

- JSPHunter: 29/29 , 100%

**2.[JSPHorse-1.3.1](https://github.com/CrackerCat/JSPHorse)与JSPHunter(0.0.9)的对抗**

​	已能全部检测出来

**3.[浅谈JspWebshell之编码](https://tttang.com/archive/1840/)**

​	文章中给出的一二三重编码能全部检测出,但不排除绕过的可能性

**4.** https://github.com/G0mini/Bypass	，https://github.com/yzddmr6/JSPBackdoor	全部检测出 

**5.https://tttang.com/archive/1739/**

​	除了"TemplatesImpl 加载字节码"，"XSLT免杀","反序列化免杀","JNDI免杀"之外，全部能检测。

​	其中"TemplatesImpl 加载字节码"，"XSLT免杀"自行将所调用的类及其方法添加到stainSource.txt，就能达到查杀效果

​	"反序列化免杀"懒得搞环境,你可以自行测试.

​	"JNDI免杀"是比较好利用的，而且因为业务经常用，所以容易误报，看个人是否愿意加入检测规则.

**已知绕过:**

- bypass文件夹下的jsp webshell

**目前正在优化检测逻辑,使检测率提高**



# 关于误报率

增强检测能力时，可能过于考虑检测，而忽略了误报率,因此待改进

误报率待测



# 使用方法

```md
基础用法:
-d "要扫描的tomcat路径"
-cp "tomcat依赖"
-del // 加此参数会自动删除恶意shell,不会删除可疑文件
-debug // 开启用户debug选项,会输出污点流方向

如：
java -cp JSPHunter.jar org.sec.Main -d D:\phpstudy_pro\Extensions\apache-tomcat-8.5.81\webapps\ROOT -cp D:\phpstudy_pro\Extensions\apache-tomcat-8.5.81\lib -del 

高级用法:
stainSource.txt为污点源文件,如果你发现新的污点源,可以手动添加到stainSource.txt,进而增强检测能力.

文件内容格式:
类 方法 方法参数和返回值 方法参数中能影响返回值的索引(0代表this,从1开始为方法参数)
如:
javax/servlet/http/HttpServletRequest	getParameter	(Ljava/lang/String;)Ljava/lang/String;	0,
```



# Refence

[Tomcat 6 --- 使用Jasper引擎解析JSP](https://www.cnblogs.com/xing901022/p/4592159.html)

[JSPKiller](https://github.com/changheluor007/JSPKiller)

[JSPFinder](https://github.com/flowerwind/JspFinder)

[使用ASM框架创建ClassVisitor时遇到IllegalArgumentException的一种可能解决办法](https://blog.csdn.net/fwhdzh/article/details/128694172)

[IDEA 错误 找不到或无法加载主类（完美解决）](https://blog.csdn.net/l_mloveforever/article/details/112725753)
