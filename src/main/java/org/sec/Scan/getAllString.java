package org.sec.Scan;

import java.util.*;

/**
 * 尝试获取该shell的一些信息,以便进一步分析
 */
public class getAllString {
    public static ArrayList<String> stringsList = new ArrayList<>();

    public static void getStringsList() {
        Set<String> set = new LinkedHashSet<>(stringsList); // 去重
        stringsList = new ArrayList<>(set);

        // 对 -info 参数进一步的过滤,将jsp文件中重复的内容过滤掉
        List<Integer> indexes = new ArrayList<>();
        for (int i = 0; i < stringsList.size(); i++) {
            if (stringsList.get(i).equals("\r\n\r\n")) {
                indexes.add(i);
            }
        }
        for(int tmpIndex : indexes){
            // 使用了四个条件来联合获取,除非看源码,否则无法绕过
            if(stringsList.get(tmpIndex+1).equals("yyyy") && stringsList.get(tmpIndex+2 ).equals("year") && stringsList.get(tmpIndex+3).equals("tomcatUrl")&& stringsList.get(tmpIndex+4).equals("https://tomcat.apache.org/")){
                stringsList.subList(stringsList.indexOf("\r\n\r\n"), stringsList.size()).clear();
            }
        }

        System.out.println("----------------------------------------------------------------");
        System.out.println("[+] 获取到的所有字符串,连接密码可能存在其中,注意是一行一个:\n[技巧:1.关注不规则字符串和常用连接密码 2.如果都试了都不行,且输出列表中存在base64编码的数据,可能密码在base64编码的数据里,需要人工进一步分析]");
        for (String s : stringsList) {
            if (s != null) {
                System.out.println(s);
            }
        }
        System.out.println("----------------------------------------------------------------");
    }

}
