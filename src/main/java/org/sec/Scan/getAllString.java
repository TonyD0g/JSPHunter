package org.sec.Scan;

import org.sec.ImitateJVM.Constant;
import org.sec.Utils.Render.ResultInfo;

import java.util.*;

/**
 * 尝试获取该shell的一些信息,以便进一步分析
 */
public class getAllString {
    public static ArrayList<String> stringsList = new ArrayList<>();
    public static void getStringsList(ResultInfo resultInfo) {
        stringsList = new ArrayList<>(new LinkedHashSet<>(stringsList));  // 去重
        // 对 -info 参数进一步的过滤,将jsp文件中重复的内容过滤掉
        List<Integer> indexes = new ArrayList<>();
        for (int i = 0; i < stringsList.size(); i++) {
            if (stringsList.get(i).equals("\r\n\r\n")) {
                indexes.add(i);
            }
        }
        // 使用了四个条件来联合获取,除非看源码,否则无法绕过
        for(int tmpIndex : indexes){
            if(stringsList.get(tmpIndex+1).equals("yyyy") && stringsList.get(tmpIndex+2 ).equals("year") && stringsList.get(tmpIndex+3).equals("tomcatUrl")&& stringsList.get(tmpIndex+4).equals("https://tomcat.apache.org/")){
                stringsList.subList(tmpIndex, stringsList.size()).clear();
                break;
            }
        }
        List<String> tempMsgList = resultInfo.getMsgList();
        tempMsgList.addAll(new ArrayList<>(stringsList));
        resultInfo.setMsgList(tempMsgList);
    }
}
