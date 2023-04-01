package org.sec.Constant;

import org.sec.Data.MethodReference;
import java.util.*;

/** 固定常量 */
public class Constant {
    public static Map<String,byte[]> classFileNameToByte=new HashMap<>();
    public static Map<String,byte[]> classNameToByte=new HashMap<>();
    public static Map<String,String> classNameToClassFileName=new HashMap<>();
    public static Map<MethodReference.Handle, Set<Integer>> passthroughDataflow=new HashMap<>();
    public static List<MethodReference.Handle> sortedMethodCalls=new ArrayList<>();
    public static Set<String> evilClass=new HashSet<String>();
    public static Map classNameToJspName=new HashMap();
    public static List<String> msgList=new ArrayList<>();
    public static boolean debug=false;
}

