package org.sec.utils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexUtils {
    /** 字符串中括号内/外的内容 */
    public static String getXXXContent(String type,String str){
        String regEx = null;
        switch (type){
            case "rightBrackets":
                regEx = "(?<=\\))(.+)";
                break;
            // 获取 普通括号()中的内容
            case "brackets":
                regEx = "(?<=\\()(.+?)(?=\\))";
                break;
            // 获取 中括号[]中的内容
            case "middleBrackets":
                regEx = "\\[(.*?)]";
                break;
            // 获取 花括号{}中的内容
            case "brace":
                regEx = "\\{(.+?)\\}";
                break;
        }


        assert regEx != null;
        Pattern pattern = Pattern.compile(regEx);
        Matcher matcher = pattern.matcher(str);
        StringBuilder stringBuilder = new StringBuilder();
        while (matcher.find()) {
            stringBuilder.append(matcher.group(1));
        }
        return stringBuilder.toString();
    }

    /**
     * 正则过滤特殊字符(1.空格 2.特殊字符[中英文])
     */
    public static String regexSpecialChair(String str) {
        String regEx = "[\\s`~!@#$%^&*()+=|{}':;',\\[\\].<>/?~！@#￥%……&*（）——+|{}【】‘；：”“’。，、？]";
        return str.replaceAll(regEx, "");
    }
}
