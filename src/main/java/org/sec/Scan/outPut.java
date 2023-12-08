package org.sec.Scan;

import org.apache.log4j.Logger;
import org.sec.Constant.Constant;
import org.sec.ImitateJVM.DebugOption;
import org.sec.Utils.FileUtils;

import java.io.File;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class outPut {
    private static final Logger logger = Logger.getLogger(outPut.class);
    public static void outPutEvilOutcomeType2(Set<Integer> printEvilMessage, String classFileName, String evilType, int anomalyDegree, boolean isDelete) {
        if (!printEvilMessage.contains(1)) {
            printEvilMessage.add(1);
            String msg;
            if (anomalyDegree == 1) {
                msg = "[+] " + "(检测结果: 恶意) " + Constant.classNameToJspName.get(classFileName) + " " + evilType + "，该文件为webshell";
            } else {
                msg = "[+] " + "(检测结果: 可疑) " + Constant.classNameToJspName.get(classFileName) + " " + evilType + "，建议查看此文件进一步判断!";
            }
            logger.info(msg);
            if (org.sec.Scan.JVMMethodScan.InvokeVirtual.getInfoFlag) {
                getAllString.getStringsList();
            }

            if (isDelete && anomalyDegree == 1) {
                String wantDelete = (String) Constant.classNameToJspName.get(classFileName);
                String realFileName = wantDelete.substring(wantDelete.lastIndexOf(File.separator) + 1);
                String path = wantDelete.substring(0, wantDelete.lastIndexOf(File.separator) + 1);
                File deleteFile = new File(path + realFileName);
                FileUtils.delete(deleteFile);
            }
            Constant.evilClass.add(classFileName);
            Constant.msgList.add(msg);
        }
    }

    public static void outPutEvilOutcomeType1(Set<Integer> printEvilMessage, String classFileName, Map<String, Set<Integer>> toEvilTaint, Set<Integer> taintList, String evilType, int anomalyDegree, boolean isDelete) {
        Set tmpTaintList = new HashSet();
        for (Object taint : taintList) {
            if (taint instanceof Integer || (taint instanceof String)) {
                outPut.outPutEvilOutcomeType2(printEvilMessage, classFileName, evilType, anomalyDegree, isDelete);
                tmpTaintList.add(taint);
            }
        }
        toEvilTaint.put(evilType, tmpTaintList);
    }
}
