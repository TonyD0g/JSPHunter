# JSPHunter [Java 8]

**基于污点分析和模拟栈帧技术的JSP Webshell检测**    

`仅做学习记录`, **85%**代码来源于JSPFinder和JSPKiller,感激这两个作品的作者.   

尝试对其进行优化检测逻辑和重构,以作为自己学习污点分析和模拟栈帧技术的检验和毕业设计.

目前正在不断更新优化，暂无可用版本.(等把webshell bypass都检测出差不多了发布正式版本)

# 个人优化

(相比于 JSPFinder,JSPKiller)

- 使用jasper 编译(JSPFinder已经实现了)

- PassthroughDiscovery 类性能比gadgetinspector的高 (JSPFinder已经实现了)

- 将 FindEvilDiscovery 中的 visitMethodInsn 抽离出来,方便于扩展

- 增强检测能力: 检测能力比JSPFinder更强,检测正常jsp文件格式不会报错

# TODO

- // todo 增强检测能力，争取能把"webshell bypass"的绕过全部检测出来(目前正在做的事)
- // todo 将白名单导出到一个文件中,使用fileUtils去读取,方便于扩展

- //todo 解决继承,实现接口能导致绕过的问题



# webshell bypass

https://github.com/threedr3am/JSP-WebShells

三个污点分析工具的检测率:

- JSPKiler: 待测

- JSPFinder:  4/29 ,  13%
- JSPHunter: 26/29 , 89%

**目前正在优化检测逻辑,使检测率提高**

# Refence

[Tomcat 6 --- 使用Jasper引擎解析JSP](https://www.cnblogs.com/xing901022/p/4592159.html)

[JSPKiller](https://github.com/changheluor007/JSPKiller)

[JSPFinder](https://github.com/flowerwind/JspFinder)
