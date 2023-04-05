package org.sec.Scan.JVMMethodScan;

import org.apache.log4j.Logger;
import org.sec.Constant.Constant;
import org.sec.Scan.FindEvilDiscovery;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

//调用接口方法
public class InvokeInterface {
    private static final Logger logger = Logger.getLogger(InvokeInterface.class);

    public static String analysis(String owner, String name, List<Set<Integer>> argTaint, Set<Integer> printEvilMessage, String classFileName, Map<String, Set<Integer>> toEvilTaint, FindEvilDiscovery.FindEvilDataflowMethodVisitor findEvilDataflowMethodVisitor) {

        boolean scriptEngineEval = owner.equals("javax/script/ScriptEngine") && name.equals("eval");
        boolean scriptEnginePut = owner.equals("javax/script/ScriptEngine") && name.equals("put");
        if (scriptEngineEval) {
            Set<Integer> taintList = argTaint.get(1);
            Set tmpTaintList = new HashSet();
            for (Object taint : taintList) {
                if (taint instanceof Integer) {
                    if (!printEvilMessage.contains(1)) {
                        printEvilMessage.add(1);
                        String msg = "[+] " + Constant.classNameToJspName.get(classFileName) + "------ScriptEngine可受request控制，该文件为webshell!!!";
                        logger.info(msg);
                        Constant.evilClass.add(classFileName);
                        Constant.msgList.add(msg);
                    }
                    tmpTaintList.add(taint);
                }
            }
            toEvilTaint.put("ScriptEngine", tmpTaintList);
        }

        if (scriptEnginePut) {
            Set<Integer> taintList = argTaint.get(2);
            Set tmpTaintList = new HashSet();
            for (Object taint : taintList) {
                if (taint instanceof Integer) {
                    if (!printEvilMessage.contains(1)) {
                        printEvilMessage.add(1);
                        String msg = "[+] " + Constant.classNameToJspName.get(classFileName) + "------ScriptEngine可受request控制，该文件为webshell!!!";
                        logger.info(msg);
                        Constant.evilClass.add(classFileName);
                        Constant.msgList.add(msg);
                    }
                    tmpTaintList.add(taint);
                }
            }
            toEvilTaint.put("ScriptEngine", tmpTaintList);
        }
        return "";
    }
}
