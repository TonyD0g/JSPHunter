package org.sec.Constant;

import org.sec.Data.MethodReference;

import java.util.*;

/**
 * 固定常量
 */
public class Constant {
    // 文件名 对应 字节
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
    public static Map classNameToJspName = new HashMap();
    // 消息列表
    public static List<String> msgList = new ArrayList<>();
}

