package org.sec.Scan.JVMMethodScan;

import org.apache.log4j.Logger;
import org.sec.Scan.FindEvilDiscovery;

import java.util.*;

public class InvokeStatic {
    private static final Logger logger = Logger.getLogger(InvokeStatic.class);

    public String analysis(int opcode, String owner, String name, String desc, boolean itf, FindEvilDiscovery.FindEvilDataflowMethodVisitor findEvilDataflowMethodVisitor, List<Set<Integer>> argTaint, Set<Integer> printEvilMessage, String classFileName, Map<String, Set<Integer>> toEvilTaint) {

        boolean isValueOf = name.equals("valueOf") && desc.equals("(Ljava/lang/Object;)Ljava/lang/String;") && owner.equals("java/lang/String");
        if (isValueOf && findEvilDataflowMethodVisitor.operandStack.get(0).size() > 0) {
            Set taintList = findEvilDataflowMethodVisitor.operandStack.get(0);
            findEvilDataflowMethodVisitor.superVisitMethod(opcode, owner, name, desc, itf);
            findEvilDataflowMethodVisitor.operandStack.get(0).addAll(taintList);
            return "void";
        }
        return "";
    }
}
