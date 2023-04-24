# JSPHunter [Java 8]

**基于污点分析和模拟栈帧技术的JSP Webshell检测**    `仅做学习记录`

我发现JSPFinder和JSPKiller模拟栈帧的部分几乎一致，因此不重复造轮子，直接在JSPFinder的基础上进行改进,所以**85%**代码来源于JSPFinder和JSPKiller,感激这两个作品的作者.   

尝试对其进行优化检测逻辑和重构,以作为自己学习污点分析和模拟栈帧技术的检验和毕业设计.

目前正在不断更新优化，欢迎师傅们提交bypass，我会进行优化改进

# 个人优化

(相比于 JSPFinder,JSPKiller)

- 使用jasper 编译(JSPFinder已经实现了)

- PassthroughDiscovery 类性能比gadgetinspector的高 (JSPFinder已经实现了)

- 将 FindEvilDiscovery 中的 visitMethodInsn 抽离出来,方便于扩展

- 增强检测能力: 检测能力比JSPFinder更强,检测正常jsp文件格式不会报错,能把"webshell bypass"的绕过全部检测出来

# TODO

- // todo 将污点源黑名单导出到一个文件中,使用fileUtils去读取,方便于扩展

- //todo 解决继承,实现接口能导致绕过的问题

- // todo 解决unicode编码导致JSPHunter报错而无法检测的问题



# webshell bypass

**1.https://github.com/threedr3am/JSP-WebShells**

三个污点分析工具的检测率:

- JSPKiler: 待测

- JSPFinder:  4/29 ,  13%
- JSPHunter: 29/29 , 100%



**2.[JSPHorse-1.3.1](https://github.com/CrackerCat/JSPHorse)与JSPHunter(0.0.7)的初次对抗**

- 成功检测出：
  - Javac型
  - classloader
  - classloader-asm
  - bcel
  - bcel-asm

- 未检测出：

  - Base型
  - expr型
  - 所有进行unicode编码的，JSPHunter编译报错了,待解决

- IDEA编译JSPHorse时报错了,未进行检测：

  - js型

  

**目前正在优化检测逻辑,使检测率提高**



# 关于误报率

增强检测能力时，可能过于考虑检测，而忽略了误报率,因此待改进

误报率待测



# 使用方法

```md
java -cp JSPHunter.jar org.sec.Main -d "要扫描的tomcat路径" -cp "tomcat\lib" -m b 

如：
java -cp JSPHunter.jar org.sec.Main -d D:\phpstudy_pro\Extensions\apache-tomcat-8.5.81\webapps\ROOT -cp D:\phpstudy_pro\Extensions\apache-tomcat-8.5.81\lib -m b 
```



# Refence

[Tomcat 6 --- 使用Jasper引擎解析JSP](https://www.cnblogs.com/xing901022/p/4592159.html)

[JSPKiller](https://github.com/changheluor007/JSPKiller)

[JSPFinder](https://github.com/flowerwind/JspFinder)

[使用ASM框架创建ClassVisitor时遇到IllegalArgumentException的一种可能解决办法](https://blog.csdn.net/fwhdzh/article/details/128694172)

[IDEA 错误 找不到或无法加载主类（完美解决）](https://blog.csdn.net/l_mloveforever/article/details/112725753)
