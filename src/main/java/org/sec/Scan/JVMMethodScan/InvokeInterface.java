package org.sec.Scan.JVMMethodScan;

import org.sec.Scan.FindEvilDiscovery;
import org.sec.Scan.outPut;

import java.util.List;
import java.util.Map;
import java.util.Set;

//调用接口方法
public class InvokeInterface {

    public static void analysis(String owner, String name, String desc, boolean itf, FindEvilDiscovery.FindEvilDataflowMethodVisitor findEvilDataflowMethodVisitor, List<Set<Integer>> argTaint, Set<Integer> printEvilMessage, String classFileName, Map<String, Set<Integer>> toEvilTaint, boolean isDelete) {

        boolean scriptEngineEval = owner.equals("javax/script/ScriptEngine") && name.equals("eval");
        boolean scriptEnginePut = owner.equals("javax/script/ScriptEngine") && name.equals("put");
        boolean isMethodAccessorInvoke = owner.equals("sun/reflect/MethodAccessor") && name.equals("invoke") && desc.equals("(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");

        if (scriptEngineEval) {
            Set<Integer> taintList = argTaint.get(1);
            outPut.outPutEvilOutcomeType1(printEvilMessage, classFileName, findEvilDataflowMethodVisitor.name, " ScriptEngine", toEvilTaint, taintList, 1, isDelete);
        }

        if (scriptEnginePut) {
            Set<Integer> taintList = argTaint.get(2);
            outPut.outPutEvilOutcomeType1(printEvilMessage, classFileName, findEvilDataflowMethodVisitor.name, " ScriptEngine", toEvilTaint, taintList, 1, isDelete);
        }
        if (isMethodAccessorInvoke) {
            Set<Integer> taintList = argTaint.get(0);
            outPut.outPutEvilOutcomeType1(printEvilMessage, classFileName, findEvilDataflowMethodVisitor.name, " MethodAccessor.Invoke", toEvilTaint, taintList, 1, isDelete);
        }
    }
}
