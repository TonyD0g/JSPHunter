package org.sec.Scan;

import java.util.*;

/** 尝试获取该shell的一些信息,以便进一步分析 */
public class getAllString {
    public static ArrayList<String> stringsList = new ArrayList<>();

    public static void getStringsList() {
        Set<String> set = new LinkedHashSet<>(stringsList); // 去重
        stringsList = new ArrayList<>(set);
        System.out.println("----------------------------------------------------------------");
        System.out.println("[+] 获取到的所有字符串,连接密码可能存在其中:\n[技巧:1.关注不规则字符串和常用连接密码 2.如果都试了都不行,且输出列表中存在base64编码的数据,可能密码在base64编码的数据里,需要人工进一步分析]");
        for (int i = 0; i < stringsList.size(); i++) {
            if(stringsList.get(i)!=null){
                System.out.println(stringsList.get(i));
            }
        }
        System.out.println("----------------------------------------------------------------");
    }

}
