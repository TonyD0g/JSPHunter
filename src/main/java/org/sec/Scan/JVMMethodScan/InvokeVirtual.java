package org.sec.Scan.JVMMethodScan;

import org.apache.log4j.Logger;
import org.objectweb.asm.Type;
import org.sec.Constant.Constant;
import org.sec.Scan.FindEvilDiscovery;

import java.io.IOException;
import java.util.*;

/**
 * 调用实例方法
 */
public class InvokeVirtual {
    private static final Logger logger = Logger.getLogger(InvokeVirtual.class);

    public String analysis(int opcode, String owner, String name, String desc, boolean itf, FindEvilDiscovery.FindEvilDataflowMethodVisitor findEvilDataflowMethodVisitor, List<Set<Integer>> argTaint, Set<Integer> printEvilMessage, String classFileName, Map<String, Set<Integer>> toEvilTaint) {

        //下面这些bool判断出了Runtime exc的，其他都是看有没有调用到字符串处理的方法，如果有字符串处理的方法，把污点传递(污点中包含字符串明文，传递到一些方法中会做对应模拟处理，比如append会把污点中的字符串相加)
        boolean subString = owner.equals("java/lang/String") && name.equals("substring");
        boolean classCallMethod = owner.equals("java/lang/Class") && (name.equals("getMethod") || name.equals("getConstructors") || name.equals("getConstructor") || name.equals("getDeclaredConstructors") || name.equals("getDeclaredConstructor") || name.equals("getDeclaredMethod"));
        boolean decodeBuffer = name.equals("decodeBuffer") && owner.equals("sun/misc/BASE64Decoder") && desc.equals("(Ljava/lang/String;)[B");
        boolean jdk8DecodeString = owner.equals("java/util/Base64$Decoder") && name.equals("decode") && desc.equals("(Ljava/lang/String;)[B");
        boolean jdk8DecodeBytes = owner.equals("java/util/Base64$Decoder") && name.equals("decode") && desc.equals("([B)[B");
        boolean exec = name.equals("exec") && owner.equals("java/lang/Runtime") & desc.contains("Ljava/lang/Process");     //把desc修改为包含返回值为Process的即为发现Runtime.exec方法，这样可以同时检测到重载的几个方法
        boolean append = name.equals("append") &&
                owner.equals("java/lang/StringBuilder") &&
                desc.equals("(Ljava/lang/String;)Ljava/lang/StringBuilder;");
        boolean toString = name.equals("toString") && owner.equals("java/lang/StringBuilder") && desc.equals("()Ljava/lang/String;");
        //这个方法比较特殊，他的污点传递是从实体类传到入参的第一个参数中，所以这里要对他特殊处理
        boolean inputStream = owner.equals("java/io/InputStream") && name.equals("read") && desc.equals("([BII)I");
        boolean methodInvoke = owner.equals("java/lang/reflect/Method") && name.equals("invoke") && desc.equals("(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
        boolean ProcessBuilderCommand = owner.equals("java/lang/ProcessBuilder") && name.equals("command") && desc.equals("([Ljava/lang/String;)Ljava/lang/ProcessBuilder;");
        boolean newInstance = (owner.equals("java/lang/reflect/Constructor") && name.equals("newInstance") && desc.equals("([Ljava/lang/Object;)Ljava/lang/Object;")) || (owner.equals("java/lang/Class") && name.equals("newInstance") && desc.equals("()Ljava/lang/Object;"));
        boolean JdbcRowSetImpl = owner.equals("com/sun/rowset/JdbcRowSetImpl") && name.equals("setDataSourceName") && desc.equals("(Ljava/lang/String;)V");
        boolean URLClassloader = (owner.equals("java/net/URLClassLoader") && name.equals("loadClass") && desc.equals("(Ljava/lang/String;)Ljava/lang/Class;"));
        boolean TemplatesImpl = (owner.equals("com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl") && name.equals("getOutputProperties") && desc.equals("()Ljava/util/Properties;"));
        boolean ELProcessor = (owner.equals("javax/el/ELProcessor") && name.equals("eval") && desc.equals("(Ljava/lang/String;)Ljava/lang/Object;"));
        boolean ExpressionFactory = (owner.equals("javax/el/ExpressionFactory") && name.equals("createValueExpression") && desc.equals("(Ljavax/el/ELContext;Ljava/lang/String;Ljava/lang/Class;)Ljavax/el/ValueExpression;"));
        boolean readObject = (name.equals("readObject") && desc.equals("()Ljava/lang/Object;"));

        if(readObject){
            if (findEvilDataflowMethodVisitor.name.equals("_jspService")) {
                if (!printEvilMessage.contains(1)) {
                    printEvilMessage.add(1);
                    String msg = null;
                    msg = "[+] " + Constant.classNameToJspName.get(classFileName) + "------调用了 readObject，可能为重写ObjectInputStream.resolveClass型webshell.,建议查看此文件进一步判断!";
                    logger.info(msg);
                    Constant.evilClass.add(classFileName);
                    Constant.msgList.add(msg);
                }
            }
            return "void";
        }
        if (ExpressionFactory) {
            Type[] argumentTypes = Type.getArgumentTypes(desc);
            Set<Integer> taints = null;
            if (findEvilDataflowMethodVisitor.operandStack.get(argumentTypes.length - 1).size() > 0) {
                taints = new HashSet<>();
                int taintNum = 0;
                for (Object node : findEvilDataflowMethodVisitor.operandStack.get(argumentTypes.length - 1)) {
                    if (node instanceof Integer || ((node instanceof String && ((String) node).contains("instruction")))) {
                        if (node instanceof Integer) {
                            taintNum = (Integer) node;
                            if (Constant.debug) {
                                logger.info("ClassLoader的defineClass可被arg" + taintNum + "污染");
                            }
                            taints.add(taintNum);
                        }

                        if (findEvilDataflowMethodVisitor.name.equals("_jspService")) {
                            if (!printEvilMessage.contains(1)) {
                                printEvilMessage.add(1);
                                String msg = Constant.classNameToJspName.get(classFileName) + "------ExpressionFactory 可受request控制，该文件为webshell";
                                logger.info(msg);
                                Constant.evilClass.add(classFileName);
                                Constant.msgList.add(msg);
                            }
                        }
                    }
                }
            }
            toEvilTaint.put("ExpressionFactory", taints);
            findEvilDataflowMethodVisitor.superVisitMethod(opcode, owner, name, desc, itf);
            return "void";
        }
        if (subString) {
            int k = 0;
            Set<Object> listAll = new HashSet<>();
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
            listAll.addAll(findEvilDataflowMethodVisitor.operandStack.get(k));
            findEvilDataflowMethodVisitor.superVisitMethod(opcode, owner, name, desc, itf);
            findEvilDataflowMethodVisitor.operandStack.get(0).addAll(listAll);
            return "void";
        }
//      //这种情况不需要判断有没有攻击者可控的参数流入，下图告警的情况会在攻击者尝试通过字符串拼接等方式得到一个ProcessBuilder和Runtime才会产生的
        if (classCallMethod) {
            int k = 0;
            for (Type argType : Type.getArgumentTypes(desc)) {
                int size = argType.getSize();
                while (size-- > 0) {
                    Set taintList = findEvilDataflowMethodVisitor.operandStack.get(k);
                    //因为前面各种方法传递、运算 字符串才会在这里得到完整得结果
                    if (taintList.contains("java.lang.ProcessBuilder") || taintList.contains("java.lang.Runtime")) {
                        //这种情况就是企图反射调用java.lang.ProcessBuilder或者java.lang.Runtime。直接调用命令执行方法可能是程序的正常业务功能，但反射调用命令执行方法基本就是攻击者行为。
                        outputEvilFilename(printEvilMessage, classFileName);
                    }
                    k++;
                }
            }
            if (findEvilDataflowMethodVisitor.operandStack.get(k).contains("java.lang.ProcessBuilder") || findEvilDataflowMethodVisitor.operandStack.get(k).contains("java.lang.Runtime")) {
                outputEvilFilename(printEvilMessage, classFileName);
            }
            findEvilDataflowMethodVisitor.superVisitMethod(opcode, owner, name, desc, itf);
            return "void";
        }
        if (decodeBuffer || jdk8DecodeString) {
            String encodeString = "";
            Set taintList = findEvilDataflowMethodVisitor.operandStack.get(0);
            int taintNum = -1;
            for (Object taint : taintList) {
                taintNum++;
                if (taint instanceof String) {
                    encodeString = (String) taint;
                    break;
                } else if (taint instanceof Integer) {
                    findEvilDataflowMethodVisitor.superVisitMethod(opcode, owner, name, desc, itf);
                    findEvilDataflowMethodVisitor.operandStack.get(0).addAll(taintList);
                    return "void";
                }
            }
            if (encodeString.length() > 0) {
                String decodeString = new String();
                try {
                    decodeString = new String(new sun.misc.BASE64Decoder().decodeBuffer(encodeString));
                } catch (IOException e) {
                    e.printStackTrace();
                }
                List newTaintList = new ArrayList<>(taintList);
                newTaintList.set(taintNum, decodeString);
                findEvilDataflowMethodVisitor.superVisitMethod(opcode, owner, name, desc, itf);
                findEvilDataflowMethodVisitor.operandStack.get(0).addAll(newTaintList);

            }
        }
        if (jdk8DecodeBytes) {
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
                    try {
                        findEvilDataflowMethodVisitor.operandStack.get(0).add(new String(new sun.misc.BASE64Decoder().decodeBuffer(new String(tmp))));
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    return "void";
                }
                //如果不包含arrayList的byte数组，那么就正常传递污点
                findEvilDataflowMethodVisitor.superVisitMethod(opcode, owner, name, desc, itf);
                findEvilDataflowMethodVisitor.operandStack.get(0).addAll(taintList);
                return "void";
            }
        }
        if (exec || ProcessBuilderCommand || newInstance || JdbcRowSetImpl || URLClassloader || TemplatesImpl || ELProcessor || readObject) {
            if (findEvilDataflowMethodVisitor.operandStack.get(0).size() > 0) {
                Set<Integer> taints = new HashSet<>();
                int taintNum;
                for (Object node : findEvilDataflowMethodVisitor.operandStack.get(0)) {
                    if (node instanceof Integer || (node instanceof String && ((String) node).contains("instruction"))) {
                        if(node instanceof Integer){
                            taintNum = (Integer) node;
                            if (Constant.debug) {
                                logger.info("Runtime.exec可被arg" + taintNum + "污染");
                            }
                            taints.add(taintNum);
                        }
                        if (findEvilDataflowMethodVisitor.name.equals("_jspService")) {
                            if (!printEvilMessage.contains(1)) {
                                printEvilMessage.add(1);
                                String msg = null;
                                if(exec){
                                    msg = "[+] " + Constant.classNameToJspName.get(classFileName) + "------Runtime.exec 可受request控制，该文件为webshell!!!";
                                }else if(ProcessBuilderCommand) {
                                    msg = "[+] " + Constant.classNameToJspName.get(classFileName) + "------ProcessBuilder 可受request控制，该文件为webshell!!!";
                                } else if(newInstance){
                                    msg = "[+] " + Constant.classNameToJspName.get(classFileName) + "------newInstance 可受request控制，该文件可能为webshell!!!,建议查看此文件";
                                }else if(JdbcRowSetImpl){
                                    msg = "[+] " + Constant.classNameToJspName.get(classFileName) + "------JdbcRowSetImpl.setDataSourceName 可受request控制，该文件可能为webshell!!!,建议查看此文件";
                                }else if(URLClassloader || TemplatesImpl){
                                    msg = "[+] " + Constant.classNameToJspName.get(classFileName) + "------URLClassloader.loadClass 或 TemplatesImpl 可受request控制，该文件可能为webshell!!!,建议查看此文件";
                                }else if(ELProcessor){
                                    msg = "[+] " + Constant.classNameToJspName.get(classFileName) + "------ELProcessor.eval 可受request控制，该文件为webshell!!!";
                                }
                                logger.info(msg);
                                Constant.evilClass.add(classFileName);
                                Constant.msgList.add(msg);
                            }
                        }
                    }
                }
                //将能够流入到Runtime.exec方法中的入参标记为污染点
                if(exec){
                    toEvilTaint.put("Runtime", taints);
                }else if(ProcessBuilderCommand){
                    toEvilTaint.put("ProcessBuilder", taints);
                }else if(newInstance){
                    toEvilTaint.put("newInstance", taints);
                }else if(JdbcRowSetImpl){
                    toEvilTaint.put("JdbcRowSetImpl", taints);
                }else if(URLClassloader){
                    toEvilTaint.put("URLClassloader", taints);
                }else if(TemplatesImpl){
                    toEvilTaint.put("TemplatesImpl", taints);
                }else if(ELProcessor){
                    toEvilTaint.put("ELProcessor", taints);
                }
                findEvilDataflowMethodVisitor.superVisitMethod(opcode, owner, name, desc, itf);
                return "void";
            }
        }
        if (append && (findEvilDataflowMethodVisitor.operandStack.get(0).size() > 0 || findEvilDataflowMethodVisitor.operandStack.get(1).size() > 0)) {
            Set taintList1 = findEvilDataflowMethodVisitor.operandStack.get(0);
            Set taintList2 = findEvilDataflowMethodVisitor.operandStack.get(1);
            findEvilDataflowMethodVisitor.superVisitMethod(opcode, owner, name, desc, itf);
            if (taintList1.size() > 0) {
                findEvilDataflowMethodVisitor.operandStack.get(0).addAll(taintList1);
            }
            if (taintList2.size() > 0) {
                findEvilDataflowMethodVisitor.operandStack.get(0).addAll(taintList2);
            }
            return "void";
        }
        if (toString && findEvilDataflowMethodVisitor.operandStack.get(0).size() > 0) {
            Set taintList = findEvilDataflowMethodVisitor.operandStack.get(0);
            findEvilDataflowMethodVisitor.superVisitMethod(opcode, owner, name, desc, itf);
            findEvilDataflowMethodVisitor.operandStack.get(0).addAll(taintList);
            return "void";
        }
        if (inputStream) {
            Type[] argumentTypes = Type.getArgumentTypes(desc);
            //operandStack.get(argumentTypes.length)表示取出实体类中的污点
            Set trains = findEvilDataflowMethodVisitor.operandStack.get(argumentTypes.length);
            if (trains.size() > 0) {
                Set tmpTaints = findEvilDataflowMethodVisitor.operandStack.get(argumentTypes.length - 1);
                for (Object tmpTaint : tmpTaints) {
                    if (tmpTaint instanceof String && ((String) tmpTaint).indexOf("instruction") > -1) {
                        String localVariablesNum = ((String) tmpTaint).substring(11);
                        findEvilDataflowMethodVisitor.localVariables.get(new Integer(localVariablesNum)).addAll(trains);
                    }
                }
            }
        }
        if (methodInvoke) {
            //表示取出method类实例上的污点
            Set<Integer> taints = argTaint.get(0);
            if (taints.size() > 0) {
                for (Object taint : taints) {
                    if (taint instanceof String && ((String) taint).equals("defineClass")) {
                        //表示取出被调用方法也就是invoke的第二个参数
                        Set<Integer> tmpTaints = argTaint.get(2);
                        Set<Integer> numTains = new HashSet<>();
                        for (Object tmpTaint : tmpTaints) {
                            //表示入参可以污染到defineClass方法的参数
                            if (tmpTaint instanceof Integer) {
                                if (!printEvilMessage.contains(1)) {
                                    printEvilMessage.add(1);
                                    String msg = Constant.classNameToJspName.get(classFileName) + "------defineClass方法反射调用后，参数可受request控制，该文件为冰蝎/哥斯拉/天蝎变种webshell";
                                    logger.info(msg);
                                    Constant.evilClass.add(classFileName);
                                    Constant.msgList.add(msg);
                                }
                                numTains.add((Integer) tmpTaint);
                            }
                        }
                        toEvilTaint.put("Behinder", numTains);
                    }
                }
            }
        }
        return "";
    }

    private void outputEvilFilename(Set<Integer> printEvilMessage, String classFileName) {
        if (!printEvilMessage.contains(1)) {
            printEvilMessage.add(1);
            String msg = "[+] " + Constant.classNameToJspName.get(classFileName) + "------企图调用ProcessBuilder或Runtime，该文件为webshell";
            logger.info(msg);
            Constant.evilClass.add(classFileName);
            Constant.msgList.add(msg);
        }
    }
}
