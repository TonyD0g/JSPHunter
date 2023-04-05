package org.sec.utils;

import org.apache.log4j.Logger;

import java.io.File;

public class stringUtils {
    private static final Logger logger = Logger.getLogger(stringUtils.class);

    /**
     * 返回被 两两分割 的数组
     */
    public static int[] splitStr(String key) {

        StringBuilder str = new StringBuilder();
        str.append(key);
        // 两两分组
        int l = 2, i = 0, m = 0;
        for (; i + m < str.length(); i++) {
            if (i % l == 0 && i != 0) {
                str.insert(i + m, ",");
                m++;
            }
        }
        i = 0;
        String se = str.toString();
        String[] a = se.split(",");
        int[] intArray = new int[key.length() / 2];
        for (; i < key.length() / 2; i++) {
            String j = a[i];
            if (j == null) {
                break;
            }

            intArray[i] = Integer.parseInt(j);
            ;
        }

        return intArray;
    }

    public static String reductionRelativePath(String path, String root) {
        String separator = "/|\\\\";
        String encodeRelativePath = path.substring(root.length() + 1);
        String[] names;
        names = encodeRelativePath.split(separator);                    //兼容windows和linux的分隔符
        StringBuilder relativePath = new StringBuilder();
        for (String name : names) {
            if (name.length() != 0) {
                relativePath.append(decodePath(name));
                relativePath.append(File.separator);
            }
        }
        return relativePath.substring(0, relativePath.length() - 1);         //抛弃最后一个\\
    }

    private static String unicodeEncoding(final String gbString) {
        char[] utfBytes = gbString.toCharArray();
        StringBuilder unicodeBytes = new StringBuilder();
        for (char utfByte : utfBytes) {
            String hexB = Integer.toHexString(utfByte);
            if (hexB.length() <= 2) {
                hexB = "00" + hexB;
            }
            unicodeBytes.append("\\u").append(hexB);
        }
        return unicodeBytes.toString();
    }

    /*
     * 由于jsp会对路径中不为java字符的字符进行unicode编码，为了将编译后的class和编译前的jsp名称能对上，这里需要将class的名字进行解码。才可以得到有问题的class其对应的jsp的名字。
     * */
    private static StringBuilder decodePath(String name) {
        String[] jspNameArr = name.split("_");
        StringBuilder afterDecodeName = new StringBuilder();
        int num = 0;
        for (String part : jspNameArr) {
            String afterDecode = null;
            if (part.length() >= 4) {
                try {
                    afterDecode = decodeUnicode("\\u" + part.substring(0, 4));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            if (part.length() >= 4 && afterDecode != null && ("\\u" + part.substring(0, 4)).equals(unicodeEncoding(afterDecode))) {
                afterDecodeName.append(afterDecode);
                afterDecodeName.append(part.substring(4));
            } else {
                if (num != 0) {
                    afterDecodeName.append(".");
                }
                afterDecodeName.append(part);
            }
            ++num;
        }
        return afterDecodeName;
    }

    private static String decodeUnicode(final String dataStr) {
        int start = 0;
        int end = 0;
        final StringBuilder buffer = new StringBuilder();
        while (start > -1) {
            end = dataStr.indexOf("\\u", start + 2);
            String charStr;
            if (end == -1) {
                charStr = dataStr.substring(start + 2);
            } else {
                charStr = dataStr.substring(start + 2, end);
            }
            char letter = 0;
            int flag = 0;
            try {
                letter = (char) Integer.parseInt(charStr, 16); // 16进制转为int,int转char
                flag = 1;
            } catch (Exception ignored) {

            }
            if (flag == 1) {
                buffer.append(letter);
            } else {
                buffer.append(charStr);
            }
            start = end;
        }
        return buffer.toString();
    }
}

