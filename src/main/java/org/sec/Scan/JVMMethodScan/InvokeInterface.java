package org.sec.Scan.JVMMethodScan;

import org.apache.log4j.Logger;
import org.objectweb.asm.Type;
import org.sec.Constant.Constant;
import org.sec.Scan.FindEvilDiscovery;
import org.sec.Scan.outPut;

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
            outPut.outPutEvilOutcomeType1(printEvilMessage, classFileName, toEvilTaint, taintList, "ScriptEngine", 1, isDelete);
            return "success";
        }

        if (scriptEnginePut) {
            Set<Integer> taintList = argTaint.get(2);
            outPut.outPutEvilOutcomeType1(printEvilMessage, classFileName, toEvilTaint, taintList, "ScriptEngine", 1, isDelete);
            return "success";
        }
        if (isMethodAccessorInvoke) {
            Set<Integer> taintList = argTaint.get(0);
            outPut.outPutEvilOutcomeType1(printEvilMessage, classFileName, toEvilTaint, taintList, "MethodAccessor.Invoke", 1, isDelete);
            return "success";
        }
        return "";
    }
}
