package org.sec.ImitateJVM;

import org.sec.Data.MethodReference;
import org.sec.Utils.Render.ResultInfo;

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

    // 记录所有的 stainSource
    public static List<String> stainSourceLines = new ArrayList<>();

    public static PrintTaint tempPrintTaint = new PrintTaint();

    public static PrintTaint finallPrintTaint = new PrintTaint();

    // 是否输出某个特定函数的反编译信息
    public static boolean isPrintDecompileInfo = false;

    // 用于统计恶意文件和可疑文件的数量
    public static int suspiciousNum = 0, maliceNum = 0;

    static {
        // debug 专用
        DebugOption.setFilter("java/lang/StringBuilder", "toString", "()Ljava/lang/String;");
    }

    //  以下是 JSPHunter 的 gui 版本专用
    public static String versionNumber = "JSPHunter (Version:   1.8.2)  Modify from TonyD0g";
    public static String dict; // jar 目录
    public static String classPath; // 依赖目录
    public static boolean isWindows = false; // 是否是windows系统
    public static boolean isOpenInfoMode = false; // 是否开启信息模式
    public static boolean isOpenDeleteMode = false; // 是否开启删除模式
    public static boolean isOpenDebugMode = false; // 是否开启debug模式


    public static Map<String, Boolean> classFileNameToIsLock = new HashMap<>(); // 文件名对应是否被锁

    public static String outputPath = ""; // 运行结果文件的输出路径

    public static List<ResultInfo> results = new ArrayList<>(); // 用于可视化输出
    public static ResultInfo resultInfo = new ResultInfo(); // 临时存储 resultInfo ,  用于检测单个文件后输出利用

}

