package org.sec.Scan.JVMMethodScan;

import org.apache.log4j.Logger;
import org.objectweb.asm.Type;
import org.sec.Constant.Constant;
import org.sec.Scan.FindEvilDiscovery;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

//调用接口方法
public class InvokeInterface {
    private static final Logger logger = Logger.getLogger(InvokeInterface.class);

    public static String analysis(String owner, String name, String desc, List<Set<Integer>> argTaint, Set<Integer> printEvilMessage, String classFileName, Map<String, Set<Integer>> toEvilTaint, FindEvilDiscovery.FindEvilDataflowMethodVisitor findEvilDataflowMethodVisitor) {

        boolean scriptEngineEval = owner.equals("javax/script/ScriptEngine") && name.equals("eval");
        boolean scriptEnginePut = owner.equals("javax/script/ScriptEngine") && name.equals("put");
        boolean isMethodAccessorInvoke = owner.equals("sun/reflect/MethodAccessor") && name.equals("invoke") && desc.equals("(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");

        if (scriptEngineEval) {
            Set<Integer> taintList = argTaint.get(1);
            outPutEvilOutcome(printEvilMessage, classFileName, toEvilTaint, taintList, "ScriptEngine");
        }

        if (scriptEnginePut) {
            Set<Integer> taintList = argTaint.get(2);
            outPutEvilOutcome(printEvilMessage, classFileName, toEvilTaint, taintList, "ScriptEngine");
        }
        if (isMethodAccessorInvoke) {
            Set<Integer> taintList = argTaint.get(0);
            outPutEvilOutcome(printEvilMessage, classFileName, toEvilTaint, taintList, "MethodAccessor.Invoke");
        }
        return "";
    }

    public static void outPutEvilOutcome(Set<Integer> printEvilMessage, String classFileName, Map<String, Set<Integer>> toEvilTaint, Set<Integer> taintList, String evilType) {
        Set tmpTaintList = new HashSet();
        for (Object taint : taintList) {
            if (taint instanceof Integer || (taint instanceof String )) {
                if (!printEvilMessage.contains(1)) {
                    printEvilMessage.add(1);
                    String msg = "[+] " + "(检测结果: 可疑) " + Constant.classNameToJspName.get(classFileName) + "   使用了" + evilType + "，建议查看此文件进一步判断!";
                    logger.info(msg);
                    Constant.evilClass.add(classFileName);
                    Constant.msgList.add(msg);
                }
                tmpTaintList.add(taint);
            }
        }
        toEvilTaint.put(evilType, tmpTaintList);
    }
}
