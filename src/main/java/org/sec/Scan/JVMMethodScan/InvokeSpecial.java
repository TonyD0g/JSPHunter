package org.sec.Scan.JVMMethodScan;

import org.objectweb.asm.Type;
import org.sec.ImitateJVM.CoreMethodAdapter;
import org.sec.ImitateJVM.currentClassQueue;
import org.sec.Scan.FindEvilDiscovery;
import org.sec.Scan.outPut;

import java.util.*;

public class InvokeSpecial {
    public static boolean analysis(int opcode, String owner, String name, String desc, boolean itf, FindEvilDiscovery.FindEvilDataflowMethodVisitor findEvilDataflowMethodVisitor, List<Set<Integer>> argTaint, Set<Integer> printEvilMessage, String classFileName, Map<String, Set<Integer>> toEvilTaint, boolean isDelete) {
        //除了ProcessBuilder,也都是做污点字符串传递的处理
        boolean processBuilderInit = owner.equals("java/lang/ProcessBuilder") && name.equals("<init>");
        boolean stringByteInit = owner.equals("java/lang/String") && name.equals("<init>") && (desc.equals("([B)V") || desc.equals("([BLjava/lang/String;)V"));
        boolean stringInit = owner.equals("java/lang/String") && name.equals("<init>");
        boolean stringBuilderInit = owner.equals("java/lang/StringBuilder") && name.equals("<init>") && desc.equals("(Ljava/lang/String;)V");
        boolean defineClass = owner.equals("java/lang/ClassLoader") && name.equals("defineClass");
        boolean URLClassLoaderInit = owner.equals("java/net/URLClassLoader") && name.equals("<init>") && desc.equals("([Ljava/net/URL;)V");
        boolean ObjectInputStreamResolveClass = owner.equals("java/io/ObjectInputStream") && name.equals("resolveClass") && desc.equals("(Ljava/io/ObjectStreamClass;)Ljava/lang/Class;");

        if (stringByteInit) {
            Set taintList = findEvilDataflowMethodVisitor.operandStack.get(0);
            for (Object taint : findEvilDataflowMethodVisitor.operandStack.get(0)) {
                //获取Opcodes.BIPUSH存放进来的byte数组然后还原原貌，主应对new String(byte[])这种情况，把byte[]还原成String进行污点传递
                if (taint instanceof ArrayList) {
                    int len = ((ArrayList<?>) taint).size();
                    byte[] tmp = new byte[len];
                    for (int i = 0; i < len; i++) {
                        tmp[i] = (byte) (int) (((ArrayList<? extends Integer>) taint).get(i));
                    }
                    findEvilDataflowMethodVisitor.visitMethodInsnForSuper(opcode, owner, name, desc, itf);
                    findEvilDataflowMethodVisitor.operandStack.get(0).add(new String(tmp));
                    return true;
                }
                //如果不包含arrayList的byte数组，那么就正常传递污点
                findEvilDataflowMethodVisitor.visitMethodInsnForSuper(opcode, owner, name, desc, itf);
                if (!CoreMethodAdapter.isSizeEqual) {
                    findEvilDataflowMethodVisitor.operandStack.get(0).addAll(taintList);
                }
                return true;
            }
        }
        if (stringInit) {
            //传递String对象初始化参数中的所有的污点
            int k = 0;
            Set listAll = new HashSet();
            k = InvokeVirtual.addTaintToOperandStack(desc, findEvilDataflowMethodVisitor, k, listAll);
            findEvilDataflowMethodVisitor.visitMethodInsnForSuper(opcode, owner, name, desc, itf);
            findEvilDataflowMethodVisitor.operandStack.get(0).addAll(listAll);
            return true;
        }
        if (processBuilderInit) {
            if (!findEvilDataflowMethodVisitor.operandStack.get(0).isEmpty()) {
                Set<Integer> taints = new HashSet<>();
                for (Object node : findEvilDataflowMethodVisitor.operandStack.get(0)) {
                    if (node instanceof Integer) {
                        int taintNum = (Integer) node;
                        taints.add(taintNum);
                        if (findEvilDataflowMethodVisitor.name.equals("_jspService") || currentClassQueue.fatherClass.equals("_jspService")) {
                            outPut.outPutEvilOutcomeType2(printEvilMessage, classFileName, findEvilDataflowMethodVisitor.name ," ProcessBuilder", 1, isDelete);
                        }
                    }
                }
                toEvilTaint.put("ProcessBuilder", taints);
                findEvilDataflowMethodVisitor.visitMethodInsnForSuper(opcode, owner, name, desc, itf);
                return true;
            }
        }

        if (stringBuilderInit && !findEvilDataflowMethodVisitor.operandStack.get(0).isEmpty()) {
            Set taintList = findEvilDataflowMethodVisitor.operandStack.get(0);
            findEvilDataflowMethodVisitor.visitMethodInsnForSuper(opcode, owner, name, desc, itf);
            findEvilDataflowMethodVisitor.operandStack.get(0).addAll(taintList);
            return true;
        }

        //只要入参能流入到defineClass方法的第1号位置参数，1号参数是字节数组，就表示是个危险方法
        if (defineClass || URLClassLoaderInit || ObjectInputStreamResolveClass) {
            Type[] argumentTypes = Type.getArgumentTypes(desc);
            //operandStack.get(argumentTypes.length-1)表示取出defineClass第1号位置的污点集合
            Set<Integer> taints = null;
            if (!findEvilDataflowMethodVisitor.operandStack.get(argumentTypes.length - 1).isEmpty()) {
                taints = new HashSet<>();
                int taintNum = 0;
                for (Object node : findEvilDataflowMethodVisitor.operandStack.get(argumentTypes.length - 1)) {
                    if (node instanceof Integer || ((node instanceof String && ((String) node).contains("instruction")))) {
                        if (node instanceof Integer) {
                            taintNum = (Integer) node;
                            taints.add(taintNum);
                        }
                        if (findEvilDataflowMethodVisitor.name.equals("_jspService") || currentClassQueue.fatherClass.equals("_jspService")) {
                            outPut.outPutEvilOutcomeType2(printEvilMessage, classFileName, findEvilDataflowMethodVisitor.name," defineClass或URLClassLoaderInit或ObjectInputStreamResolveClass", 1, isDelete);
                        }
                    }
                }
            }
            toEvilTaint.put("Behinder", taints);
            findEvilDataflowMethodVisitor.visitMethodInsnForSuper(opcode, owner, name, desc, itf);
            return true;
        }
        return false;
    }
}
