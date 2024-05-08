package org.sec.Scan.JVMMethodScan;

import org.sec.ImitateJVM.currentClassQueue;
import org.sec.Scan.FindEvilDiscovery;
import org.sec.Scan.outPut;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class InvokeStatic {
    public static boolean analysis(int opcode, String owner, String name, String desc, boolean itf, FindEvilDiscovery.FindEvilDataflowMethodVisitor findEvilDataflowMethodVisitor, List<Set<Integer>> argTaint, Set<Integer> printEvilMessage, String classFileName, Map<String, Set<Integer>> toEvilTaint, boolean isDelete) {
        boolean isValueOf = name.equals("valueOf") && desc.equals("(Ljava/lang/Object;)Ljava/lang/String;") && owner.equals("java/lang/String");
        boolean isMethodUtilInvoke = owner.equals("sun/reflect/misc/MethodUtil") && name.equals("invoke") && desc.equals("(Ljava/lang/reflect/Method;Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
        boolean JspRuntimeLibrary = owner.equals("org/apache/jasper/runtime/JspRuntimeLibrary") && name.equals("introspect") && desc.equals("(Ljava/lang/Object;Ljavax/servlet/ServletRequest;)V");
        // boolean TransformerFactory = owner.equals("javax/xml/transform/TransformerFactory") && name.equals("newInstance") && desc.equals("()Ljavax/xml/transform/TransformerFactory;");

        if ((isMethodUtilInvoke || JspRuntimeLibrary) && !findEvilDataflowMethodVisitor.operandStack.get(0).isEmpty()) {
            Set<Integer> taints = new HashSet<>();
            for (Object node : findEvilDataflowMethodVisitor.operandStack.get(0)) {
                if (node instanceof Integer) {
                    int taintNum = (Integer) node;
                    taints.add(taintNum);
                    if (findEvilDataflowMethodVisitor.name.equals("_jspService") || currentClassQueue.fatherClass.equals("_jspService")) {
                        if (isMethodUtilInvoke) {
                            outPut.outPutEvilOutcomeType2(printEvilMessage, classFileName, findEvilDataflowMethodVisitor.name," MethodUtil.invoke", 1, isDelete);
                        } else {
                            outPut.outPutEvilOutcomeType2(printEvilMessage, classFileName, findEvilDataflowMethodVisitor.name," JspRuntimeLibrary,可能为利用jsp标签属性注入字符串解析", 2, isDelete);
                        }
                        break;
                    }
                }
            }
            findEvilDataflowMethodVisitor.visitMethodInsnForSuper(opcode, owner, name, desc, itf);
            return true;
        }

        if ((isValueOf) && !findEvilDataflowMethodVisitor.operandStack.get(0).isEmpty()) {
            Set taintList = findEvilDataflowMethodVisitor.operandStack.get(0);
            findEvilDataflowMethodVisitor.visitMethodInsnForSuper(opcode, owner, name, desc, itf);
            findEvilDataflowMethodVisitor.operandStack.get(0).addAll(taintList);
            return true;
        }
        return false;
    }
}