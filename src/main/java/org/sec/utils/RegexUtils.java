package org.sec.utils;

public class RegexUtils {
    /**
     * 正则过滤特殊字符(1.空格 2.特殊字符[中英文])
     */
    public static String regexSpecialChair(String str) {
        String regEx = "[\\s`~!@#$%^&*()+=|{}':;',\\[\\].<>/?~！@#￥%……&*（）——+|{}【】‘；：”“’。，、？]";
        return str.replaceAll(regEx, "");
    }
}
