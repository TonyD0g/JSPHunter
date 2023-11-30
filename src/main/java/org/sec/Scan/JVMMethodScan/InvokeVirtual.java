package org.sec.Scan.JVMMethodScan;

import org.apache.log4j.Logger;
import org.objectweb.asm.Type;
import org.sec.Constant.Constant;
import org.sec.ImitateJVM.DebugOption;
import org.sec.ImitateJVM.currentClassQueue;
import org.sec.Scan.FindEvilDiscovery;
import org.sec.Scan.getAllString;
import org.sec.Scan.outPut;
import org.sec.Utils.FileUtils;

import java.io.File;
import java.io.IOException;
import java.util.*;

/**
 * 调用实例方法
 */
public class InvokeVirtual {
    private static final Logger logger = Logger.getLogger(InvokeVirtual.class);
    public static boolean getInfoFlag = false;

    public String analysis(int opcode, String owner, String name, String desc, boolean itf, FindEvilDiscovery.FindEvilDataflowMethodVisitor findEvilDataflowMethodVisitor, List<Set<Integer>> argTaint, Set<Integer> printEvilMessage, String classFileName, Map<String, Set<Integer>> toEvilTaint, boolean isDelete) {

        //下面这些bool判断出了Runtime exc的，其他都是看有没有调用到字符串处理的方法，如果有字符串处理的方法，把污点传递(污点中包含字符串明文，传递到一些方法中会做对应模拟处理，比如append会把污点中的字符串相加)
        boolean subString = owner.equals("java/lang/String") && name.equals("substring");
        boolean classCallMethod = owner.equals("java/lang/Class") && (name.equals("getMethod") || name.equals("getConstructors") || name.equals("getConstructor") || name.equals("getDeclaredConstructors") || name.equals("getDeclaredConstructor") || name.equals("getDeclaredMethod"));
        boolean decodeBuffer = name.equals("decodeBuffer") && owner.equals("sun/misc/BASE64Decoder") && desc.equals("(Ljava/lang/String;)[B");
        boolean jdk8DecodeString = owner.equals("java/util/Base64$Decoder") && name.equals("decode") && desc.equals("(Ljava/lang/String;)[B");
        boolean jdk8DecodeBytes = owner.equals("java/util/Base64$Decoder") && name.equals("decode") && desc.equals("([B)[B");
        boolean exec = name.equals("exec") && owner.equals("java/lang/Runtime") & desc.contains("Ljava/lang/Process");     //把desc修改为包含返回值为Process的即为发现Runtime.exec方法，这样可以同时检测到重载的几个方法
        boolean append = name.equals("append") && owner.equals("java/lang/StringBuilder") && desc.equals("(Ljava/lang/String;)Ljava/lang/StringBuilder;");
        boolean toString = name.equals("toString") && owner.equals("java/lang/StringBuilder") && desc.equals("()Ljava/lang/String;");
        //这个方法比较特殊，他的污点传递是从实体类传到入参的第一个参数中，所以这里要对他特殊处理
        boolean inputStream = owner.equals("java/io/InputStream") && name.equals("read") && desc.equals("([BII)I");
        boolean methodInvoke = owner.equals("java/lang/reflect/Method") && name.equals("invoke") && desc.equals("(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
        boolean ProcessBuilderCommand = owner.equals("java/lang/ProcessBuilder") && name.equals("command") && desc.equals("([Ljava/lang/String;)Ljava/lang/ProcessBuilder;");
        boolean newInstance = (owner.equals("java/lang/reflect/Constructor") && name.equals("newInstance") && desc.equals("([Ljava/lang/Object;)Ljava/lang/Object;")) || (owner.equals("java/lang/Class") && name.equals("newInstance") && desc.equals("()Ljava/lang/Object;"));
        boolean JdbcRowSetImpl = owner.equals("com/sun/rowset/JdbcRowSetImpl") && name.equals("setDataSourceName") && desc.equals("(Ljava/lang/String;)V");
        boolean URLClassloader = (owner.equals("java/net/URLClassLoader") && name.equals("loadClass") && desc.equals("(Ljava/lang/String;)Ljava/lang/Class;"));
        boolean TemplatesImplGetter = (owner.equals("com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl") && name.equals("getOutputProperties") && desc.equals("()Ljava/util/Properties;"));
        boolean TemplatesImplNewTransformer = (owner.equals("com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl") && name.equals("newTransformer") && desc.equals("()Ljavax/xml/transform/Transformer;"));
        boolean ELProcessor = (owner.equals("javax/el/ELProcessor") && name.equals("eval") && desc.equals("(Ljava/lang/String;)Ljava/lang/Object;"));
        boolean ExpressionFactory = (owner.equals("javax/el/ExpressionFactory") && name.equals("createValueExpression") && desc.equals("(Ljavax/el/ELContext;Ljava/lang/String;Ljava/lang/Class;)Ljavax/el/ValueExpression;"));
        boolean readObject = (name.equals("readObject") && desc.equals("()Ljava/lang/Object;"));
        boolean expr = owner.equals("java/beans/Expression") && name.equals("getValue") && desc.equals("()Ljava/lang/Object;");
        boolean TransformerFactory = owner.equals("javax/xml/transform/TransformerFactory") && name.equals("newTransformer") && desc.equals("(Ljavax/xml/transform/Source;)Ljavax/xml/transform/Transformer;");

        if (readObject) {
            if (findEvilDataflowMethodVisitor.name.equals("_jspService") || currentClassQueue.fatherClass.equals("_jspService")) {
                outPut.outPutEvilOutcomeType2(printEvilMessage, classFileName, "readObject,可能为重写ObjectInputStream.resolveClass型webshell", 2, isDelete);
            }
            return "void";
        }
        if (ExpressionFactory) {
            Type[] argumentTypes = Type.getArgumentTypes(desc);
            Set<Integer> taints = null;
            if (!findEvilDataflowMethodVisitor.operandStack.get(argumentTypes.length - 1).isEmpty()) {
                taints = new HashSet<>();
                int taintNum;
                for (Object node : findEvilDataflowMethodVisitor.operandStack.get(argumentTypes.length - 1)) {
                    if (node instanceof Integer || ((node instanceof String && ((String) node).contains("instruction")))) {
                        if (node instanceof Integer) {
                            taintNum = (Integer) node;
                            if (DebugOption.userDebug) {
                                logger.info("ClassLoader的defineClass可被arg" + taintNum + "污染");
                            }
                            taints.add(taintNum);
                        }

                        if (findEvilDataflowMethodVisitor.name.equals("_jspService") || currentClassQueue.fatherClass.equals("_jspService")) {
                            outPut.outPutEvilOutcomeType2(printEvilMessage, classFileName, "ExpressionFactory,且参数外部可控", 1, isDelete);
                            if (DebugOption.userDebug) {
                                Constant.currentPrintTaint.printCurrentTaintStack("ClassLoader的defineClass ");
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
                    if (!taintList.isEmpty()) {
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
                        outPut.outPutEvilOutcomeType2(printEvilMessage, classFileName, "ProcessBuilder 或 Runtime,且参数外部可控", 1, isDelete);
                    }
                    k++;
                }
            }
            if (findEvilDataflowMethodVisitor.operandStack.get(k).contains("java.lang.ProcessBuilder") || findEvilDataflowMethodVisitor.operandStack.get(k).contains("java.lang.Runtime")) {
                outPut.outPutEvilOutcomeType2(printEvilMessage, classFileName, "ProcessBuilder 或 Runtime,且参数外部可控", 1, isDelete);
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
        if (TransformerFactory || exec || ProcessBuilderCommand || newInstance || JdbcRowSetImpl || URLClassloader || TemplatesImplGetter || TemplatesImplNewTransformer || ELProcessor || readObject || methodInvoke || expr) {
            if (!findEvilDataflowMethodVisitor.operandStack.get(0).isEmpty()) {
                Set<Integer> taints = new HashSet<>();
                int taintNum;
                for (Object node : findEvilDataflowMethodVisitor.operandStack.get(0)) {
                    if (node instanceof Integer || (node instanceof String && ((String) node).contains("instruction"))) {
                        if (node instanceof Integer) {
                            taintNum = (Integer) node;
                            taints.add(taintNum);
                        }
                        try{
                            if (findEvilDataflowMethodVisitor.name.equals("_jspService") || currentClassQueue.fatherClass.equals("_jspService")) {
                                if (DebugOption.userDebug) {
                                    Constant.currentPrintTaint.printCurrentTaintStack(" ");
                                }
                                if (exec) {
                                    outPut.outPutEvilOutcomeType2(printEvilMessage, classFileName, "Runtime.exec,且参数外部可控", 1, isDelete);
                                    break;
                                } else if (ProcessBuilderCommand) {
                                    outPut.outPutEvilOutcomeType2(printEvilMessage, classFileName, "ProcessBuilder,且参数外部可控", 1, isDelete);
                                    break;
                                } else if (newInstance) {
                                    outPut.outPutEvilOutcomeType2(printEvilMessage, classFileName, "newInstance,且参数外部可控", 2, isDelete);
                                    break;
                                } else if (JdbcRowSetImpl) {
                                    outPut.outPutEvilOutcomeType2(printEvilMessage, classFileName, "JdbcRowSetImpl.setDataSourceName,且参数外部可控", 2, isDelete);
                                    break;
                                } else if (URLClassloader) {
                                    outPut.outPutEvilOutcomeType2(printEvilMessage, classFileName, "URLClassloader.loadClass,且参数外部可控", 2, isDelete);
                                    break;
                                } else if (ELProcessor) {
                                    outPut.outPutEvilOutcomeType2(printEvilMessage, classFileName, "ELProcessor.eval,且参数外部可控", 1, isDelete);
                                    break;
                                } else if (methodInvoke) {
                                    outPut.outPutEvilOutcomeType2(printEvilMessage, classFileName, "methodInvoke,且参数外部可控", 1, isDelete);
                                    break;
                                } else if (expr) {
                                    outPut.outPutEvilOutcomeType2(printEvilMessage, classFileName, "Expression.getValue,且参数外部可控", 2, isDelete);
                                    break;
                                }else if(TransformerFactory){
                                    outPut.outPutEvilOutcomeType2(printEvilMessage, classFileName, "TransformerFactory,且参数外部可控", 1, isDelete);
                                    break;
                                }else if(TemplatesImplGetter|| TemplatesImplNewTransformer){
                                    outPut.outPutEvilOutcomeType2(printEvilMessage, classFileName, "TemplatesImpl.getOutputProperties 或 TemplatesImpl.newTransformer,且参数外部可控", 2, isDelete);
                                    break;
                                }
                            }
                        }catch (Exception e){
                            System.out.println("[-] 该文件分析失败:    "+Constant.classNameToJspName.get(classFileName));
                        }

                    }
                }
                //将能够流入到Runtime.exec方法中的入参标记为污染点
                if (exec) {
                    toEvilTaint.put("Runtime", taints);
                } else if (ProcessBuilderCommand) {
                    toEvilTaint.put("ProcessBuilder", taints);
                } else if (newInstance) {
                    toEvilTaint.put("newInstance", taints);
                } else if (JdbcRowSetImpl) {
                    toEvilTaint.put("JdbcRowSetImpl", taints);
                } else if (URLClassloader) {
                    toEvilTaint.put("URLClassloader", taints);
                } else if (TemplatesImplGetter || TemplatesImplNewTransformer) {
                    toEvilTaint.put("TemplatesImpl", taints);
                } else if (ELProcessor) {
                    toEvilTaint.put("ELProcessor", taints);
                } else if (methodInvoke) {
                    toEvilTaint.put("methodInvoke", taints);
                } else if (expr) {
                    toEvilTaint.put("expr", taints);
                }else if(TransformerFactory){
                    toEvilTaint.put("TransformerFactory", taints);
                }
                findEvilDataflowMethodVisitor.superVisitMethod(opcode, owner, name, desc, itf);
                return "void";
            }
        }
        if (append && (!findEvilDataflowMethodVisitor.operandStack.get(0).isEmpty() || !findEvilDataflowMethodVisitor.operandStack.get(1).isEmpty())) {
            Set taintList1 = findEvilDataflowMethodVisitor.operandStack.get(0);
            Set taintList2 = findEvilDataflowMethodVisitor.operandStack.get(1);
            findEvilDataflowMethodVisitor.superVisitMethod(opcode, owner, name, desc, itf);
            if (!taintList1.isEmpty()) {
                findEvilDataflowMethodVisitor.operandStack.get(0).addAll(taintList1);
            }
            if (!taintList2.isEmpty()) {
                findEvilDataflowMethodVisitor.operandStack.get(0).addAll(taintList2);
            }
            return "void";
        }
        if (toString && !findEvilDataflowMethodVisitor.operandStack.get(0).isEmpty()) {
            Set taintList = findEvilDataflowMethodVisitor.operandStack.get(0);
            findEvilDataflowMethodVisitor.superVisitMethod(opcode, owner, name, desc, itf);
            findEvilDataflowMethodVisitor.operandStack.get(0).addAll(taintList);
            return "void";
        }
        if (inputStream) {
            Type[] argumentTypes = Type.getArgumentTypes(desc);
            //operandStack.get(argumentTypes.length)表示取出实体类中的污点
            Set trains = findEvilDataflowMethodVisitor.operandStack.get(argumentTypes.length);
            if (!trains.isEmpty()) {
                Set tmpTaints = findEvilDataflowMethodVisitor.operandStack.get(argumentTypes.length - 1);
                for (Object tmpTaint : tmpTaints) {
                    if (tmpTaint instanceof String && ((String) tmpTaint).contains("instruction")) {
                        String localVariablesNum = ((String) tmpTaint).substring(11);
                        findEvilDataflowMethodVisitor.localVariables.get(new Integer(localVariablesNum)).addAll(trains);
                    }
                }
            }
        }
        if (methodInvoke) {
            //表示取出method类实例上的污点
            Set<Integer> taints = argTaint.get(0);
            if (!taints.isEmpty()) {
                for (Object taint : taints) {
                    if (taint instanceof String && taint.equals("defineClass")) {
                        //表示取出被调用方法也就是invoke的第二个参数
                        Set<Integer> tmpTaints = argTaint.get(2);
                        Set<Integer> numbTrains = new HashSet<>();
                        for (Object tmpTaint : tmpTaints) {
                            //表示入参可以污染到defineClass方法的参数
                            if (tmpTaint instanceof Integer) {
                                outPut.outPutEvilOutcomeType2(printEvilMessage, classFileName, "defineClass,且参数外部可控", 1, isDelete);
                                numbTrains.add((Integer) tmpTaint);
                            }
                        }
                        toEvilTaint.put("Behinder", numbTrains);
                    }
                }
            }
        }
        return "";
    }
}
