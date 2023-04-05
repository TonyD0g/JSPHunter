package org.sec.Scan.JVMMethodScan;

import org.apache.log4j.Logger;
import org.objectweb.asm.Type;
import org.sec.Constant.Constant;
import org.sec.Scan.FindEvilDiscovery;

import java.util.*;

/**
 * 调用构造方法
 */
public class InvokeSpecial {
    private static final Logger logger = Logger.getLogger(InvokeSpecial.class);

    public String analysis(int opcode, String owner, String name, String desc, boolean itf, FindEvilDiscovery.FindEvilDataflowMethodVisitor findEvilDataflowMethodVisitor, Set<Integer> printEvilMessage, String classFileName, Map<String, Set<Integer>> toEvilTaint) {

        //除了ProcessBuilder,也都是做污点字符串传递的处理
        boolean processBuilderInit = owner.equals("java/lang/ProcessBuilder") && name.equals("<init>");
        boolean stringByteInit = owner.equals("java/lang/String") && name.equals("<init>") && (desc.equals("([B)V") || desc.equals("([BLjava/lang/String;)V"));
        boolean stringInit = owner.equals("java/lang/String") && name.equals("<init>");
        boolean stringBuilderInit = owner.equals("java/lang/StringBuilder") && name.equals("<init>") && desc.equals("(Ljava/lang/String;)V");
        boolean defineClass = owner.equals("java/lang/ClassLoader") && name.equals("defineClass");
        if (stringByteInit) {
            Set taintList = findEvilDataflowMethodVisitor.operandStack.get(0);
            for (Object taint : findEvilDataflowMethodVisitor.operandStack.get(0)) {
                //获取Opcodes.BIPUSH存放进来的byte数组然后还原原貌，主应对new String(byte[])这种情况，把byte[]还原成String进行污点传递
                if (taint instanceof ArrayList) {
                    int len = ((ArrayList) taint).size();
                    byte[] tmp = new byte[len];
                    for (int i = 0; i < len; i++) {
                        tmp[i] = (byte) (int) (((ArrayList) taint).get(i));
                    }
                    findEvilDataflowMethodVisitor.superVisitMethod(opcode, owner, name, desc, itf);
                    findEvilDataflowMethodVisitor.operandStack.get(0).add(new String(tmp));
                    return "void";
                }
                //如果不包含arrayList的byte数组，那么就正常传递污点
                findEvilDataflowMethodVisitor.superVisitMethod(opcode, owner, name, desc, itf);
                findEvilDataflowMethodVisitor.operandStack.get(0).addAll(taintList);
                return "void";
            }
        }
        if (stringInit) {
            //传递String对象初始化参数中的所有的污点
            int k = 0;
            Set listAll = new HashSet();
            for (Type argType : Type.getArgumentTypes(desc)) {
                int size = argType.getSize();
                while (size-- > 0) {
                    Set taintList = findEvilDataflowMethodVisitor.operandStack.get(k);
                    if (taintList.size() > 0) {
                        listAll.addAll(taintList);
                    }
                    k++;
                }
            }
            findEvilDataflowMethodVisitor.superVisitMethod(opcode, owner, name, desc, itf);
            findEvilDataflowMethodVisitor.operandStack.get(0).addAll(listAll);
            return "void";
        }
        if (processBuilderInit) {
            if (findEvilDataflowMethodVisitor.operandStack.get(0).size() > 0) {
                Set<Integer> taints = new HashSet<>();
                for (Object node : findEvilDataflowMethodVisitor.operandStack.get(0)) {
                    if (node instanceof Integer) {
                        int taintNum = (Integer) node;
                        if (Constant.debug) {
                            logger.info("ProcessBuilder可被arg" + taintNum + "污染");
                        }
                        taints.add(taintNum);
                        if (findEvilDataflowMethodVisitor.name.equals("_jspService")) {
                            if (!printEvilMessage.contains(1)) {
                                printEvilMessage.add(1);
                                String msg = "[+] " + Constant.classNameToJspName.get(classFileName) + "   ProcessBuilder可受request控制，该文件为webshell!!!";
                                logger.info(msg);
                                Constant.evilClass.add(classFileName);
                                Constant.msgList.add(msg);
                            }
                        }
                    }
                }
                toEvilTaint.put("ProcessBuilder", taints);
                findEvilDataflowMethodVisitor.superVisitMethod(opcode, owner, name, desc, itf);
                return "void";
            }
        }

        if (stringBuilderInit && findEvilDataflowMethodVisitor.operandStack.get(0).size() > 0) {
            Set taintList = findEvilDataflowMethodVisitor.operandStack.get(0);
            findEvilDataflowMethodVisitor.superVisitMethod(opcode, owner, name, desc, itf);
            findEvilDataflowMethodVisitor.operandStack.get(0).addAll(taintList);
            return "void";
        }

        //只要入参能流入到defineClass方法的第1号位置参数，1号参数是字节数组，就表示是个危险方法
        if (defineClass) {
            Type[] argumentTypes = Type.getArgumentTypes(desc);
            //operandStack.get(argumentTypes.length-1)表示取出defineClass第1号位置的污点集合
            if (findEvilDataflowMethodVisitor.operandStack.get(argumentTypes.length - 1).size() > 0) {
                Set<Integer> taints = new HashSet<>();
                for (Object node : findEvilDataflowMethodVisitor.operandStack.get(argumentTypes.length - 1)) {
                    if (node instanceof Integer) {
                        int taintNum = (Integer) node;
                        if (Constant.debug) {
                            logger.info("ClassLoader的defineClass可被arg" + taintNum + "污染");
                        }
                        taints.add(taintNum);
                        if (findEvilDataflowMethodVisitor.name.equals("_jspService")) {
                            if (!printEvilMessage.contains(1)) {
                                printEvilMessage.add(1);
                                String msg = Constant.classNameToJspName.get(classFileName) + "------ClassLoader的defineClass可受request控制，该文件为多功能webshell(冰蝎等)!!!";
                                logger.info(msg);
                                Constant.evilClass.add(classFileName);
                                Constant.msgList.add(msg);
                            }
                        }
                    }
                }
                toEvilTaint.put("Behinder", taints);
                findEvilDataflowMethodVisitor.superVisitMethod(opcode, owner, name, desc, itf);
                return "void";
            }
        }
        return "";
    }
}
