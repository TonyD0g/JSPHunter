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

    public static String analysis(String owner, String name, String desc, List<Set<Integer>> argTaint, Set<Integer> printEvilMessage, String classFileName, Map<String, Set<Integer>> toEvilTaint, boolean isDelete) {

        boolean scriptEngineEval = owner.equals("javax/script/ScriptEngine") && name.equals("eval");
        boolean scriptEnginePut = owner.equals("javax/script/ScriptEngine") && name.equals("put");
        boolean isMethodAccessorInvoke = owner.equals("sun/reflect/MethodAccessor") && name.equals("invoke") && desc.equals("(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");

        if (scriptEngineEval) {
            Set<Integer> taintList = argTaint.get(1);
            outPutEvilOutcome(printEvilMessage, classFileName, toEvilTaint, taintList, "ScriptEngine", 1, isDelete);
        }

        if (scriptEnginePut) {
            Set<Integer> taintList = argTaint.get(2);
            outPutEvilOutcome(printEvilMessage, classFileName, toEvilTaint, taintList, "ScriptEngine", 1, isDelete);
        }
        if (isMethodAccessorInvoke) {
            Set<Integer> taintList = argTaint.get(0);
            outPutEvilOutcome(printEvilMessage, classFileName, toEvilTaint, taintList, "MethodAccessor.Invoke", 1, isDelete);
        }
        return "";
    }

    public static void outPutEvilOutcome(Set<Integer> printEvilMessage, String classFileName, Map<String, Set<Integer>> toEvilTaint, Set<Integer> taintList, String evilType, int anomalyDegree, boolean isDelete) {
        Set tmpTaintList = new HashSet();
        for (Object taint : taintList) {
            if (taint instanceof Integer || (taint instanceof String)) {
                InvokeVirtual.outPutEvilOutcome(printEvilMessage, classFileName, evilType, anomalyDegree, isDelete);
                tmpTaintList.add(taint);
            }
        }
        toEvilTaint.put(evilType, tmpTaintList);
    }
}
