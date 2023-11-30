package org.sec.Constant;

import org.sec.Data.MethodReference;
import org.sec.ImitateJVM.DebugOption;
import org.sec.ImitateJVM.PrintTaint;
//import org.sec.Vuln.Spring.SpringController;

import java.util.*;

/**
 * 固定常量
 */
public class Constant {
    // 文件名 对应 字节,比如 demo.class 中就是 demo 对应字节
    public static Map<String, byte[]> classFileNameToByte = new HashMap<>();
    // 类名 对应 字节
    public static Map<String, byte[]> classNameToByte = new HashMap<>();
    // class名 对应 class文件名
    public static Map<String, String> classNameToClassFileName = new HashMap<>();
    // 编译错误的文件名列表
    public static Map<Integer, String> compileErrorFileNameList = new HashMap<>();
    // 传递污点流
    public static Map<MethodReference.Handle, Set<Integer>> passthroughDataflow = new HashMap<>();
    // 整理方法调用
    public static List<MethodReference.Handle> sortedMethodCalls = new ArrayList<>();
    // 恶意类
    public static Set<String> evilClass = new HashSet<>();
    // class文件名 对应 JSP文件名
    public static Map<Object, Object> classNameToJspName = new HashMap<>();
    // 消息列表
    public static List<String> msgList = new ArrayList<>();
    // 所有类中的注解列表,键为类名,值为该类中的所有注解
    public static Map<String, Set<String>> allAnnotationsList = new HashMap<>();
    // spring Controller
    //public static final List<SpringController> allControllers = new ArrayList<>();
    // 污点源
    public static ArrayList<Object[]> PASSTHROUGH_DATAFLOW = new ArrayList<>();

    // method 名字对应 method 内容
    public static final Map<MethodReference.Handle, MethodReference> methodMap = new HashMap<>();

    public static List<String> lines = new ArrayList<>();

    public static PrintTaint currentPrintTaint = new PrintTaint();

    static {
        DebugOption.setFilter("java/lang/StringBuilder", "toString", "()Ljava/lang/String;");
    }
}

