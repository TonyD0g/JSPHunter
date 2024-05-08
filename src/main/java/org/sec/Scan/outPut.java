package org.sec.Scan;

import org.sec.ImitateJVM.Constant;
import org.sec.ImitateJVM.DebugOption;
import org.sec.Utils.FileUtils;
import org.sec.Utils.Render.ResultInfo;

import java.io.File;
import java.util.*;

public class outPut {
    public static void outPutEvilOutcomeType2(Set<Integer> printEvilMessage, String classFileName, String funcName, String evilType, int anomalyDegree, boolean isDelete) {
        if (!printEvilMessage.contains(1)) {
            ResultInfo resultInfo = new ResultInfo();
            resultInfo.setJspFilePath((String) Constant.classNameToJspName.get(classFileName));
            printEvilMessage.add(1);
            if (anomalyDegree == 1) {
                resultInfo.setAnomalyDegree("恶意");
                resultInfo.setDetails(String.format("%s 函数使用了 %s,且参数外部可控,该文件为webshell", funcName, evilType));
                Constant.maliceNum++;
            } else {
                resultInfo.setAnomalyDegree("可疑");
                resultInfo.setDetails(String.format("%s 函数使用了 %s,且参数外部可控,建议查看此文件进一步判断!", funcName, evilType));
                Constant.suspiciousNum++;
            }
            if (Constant.isOpenInfoMode) {
                getAllString.getStringsList(resultInfo);
                getAllString.stringsList.clear();
            }
            if (isDelete && anomalyDegree == 1) {
                String wantDelete = (String) Constant.classNameToJspName.get(classFileName);
                String realFileName = wantDelete.substring(wantDelete.lastIndexOf(File.separator) + 1);
                if (realFileName.charAt(0) == '.') {
                    realFileName = realFileName.replaceFirst("\\.", "");
                }
                String path = wantDelete.substring(0, wantDelete.lastIndexOf(File.separator) + 1);
                File deleteFile = new File(path + realFileName);
                FileUtils.delete(deleteFile);
            }

            Constant.evilClass.add(classFileName);
            Constant.resultInfo = resultInfo;
            Constant.results.add(Constant.resultInfo);
        }
    }

    public static void outPutEvilOutcomeType1(Set<Integer> printEvilMessage, String classFileName, String funcName, String evilType, Map<String, Set<Integer>> toEvilTaint, Set<Integer> taintList, int anomalyDegree, boolean isDelete) {
        Set tmpTaintList = new HashSet();
        for (Object taint : taintList) {
            if (taint instanceof Integer || (taint instanceof String)) {
                outPut.outPutEvilOutcomeType2(printEvilMessage, classFileName, funcName, evilType, anomalyDegree, isDelete);
                tmpTaintList.add(taint);
            }
        }
        toEvilTaint.put(evilType, tmpTaintList);
    }
}
