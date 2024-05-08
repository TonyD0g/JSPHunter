package org.sec.Utils;

import org.apache.log4j.Logger;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.regex.Pattern;

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
        }

        return intArray;
    }

    /** 根据长度返回随机字符串 */
    public static String getRandomString(int length){
        String str="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        Random random=new Random();
        StringBuilder sb=new StringBuilder();
        for(int i=0;i<length;i++){
            int number=random.nextInt(62);
            sb.append(str.charAt(number));
        }
        return sb.toString();
    }

    /** 依据某个符号进行分割,如 splitBySymbol("A-B","-") 切割为 A和B */
    public static String[] splitBySymbol(String str,String regex){
        StringBuilder[] stringBuilder = new StringBuilder[2];
        return str.split(regex);
    }

    /**
     * 对类型进行处理,如Ljava.lang.Object;中的L和java.lang.Object
     *
     */
    public static String[] handleFieldType(String str) {
        /* 如Ljava.lang.Object;  就要被拆开为  L java.lang.Object ;
         主要有这几种类型: B - byte，C - char，D - double，F - float，I - int，J - long，S - short，Z - boolean，V - void，L - 对象类型( 如Ljava/lang/String; )，数组 - 每一个维度前置使用[表示
           (这几种类型可以随意组合!,所以要做好对应的处理,如 IL java/lang/String;)
        */
        String[] tmpFieldType = new String[2];

        // 这里可能写的有问题,我的写法是: 判断"java"在字符串中的位置,然后以此进行分割字符串
        int index = str.indexOf("java");
        if (index > 0) {
            tmpFieldType[0] = str.substring(0, index);
            tmpFieldType[1] = str.substring(index, str.length() - 1);
        } else {
            tmpFieldType[0] = str.substring(0, 1);
            tmpFieldType[1] = str.substring(1, str.length() - 1);
        }
        // ILO => IL 0 3个
        System.out.println(tmpFieldType[0].getBytes(StandardCharsets.UTF_8).length);
        String[] fieldType = new String[tmpFieldType[0].getBytes(StandardCharsets.UTF_8).length + 1];
        // 如 ILjava/lang/String; 将 java/lang/String 存放到 fieldType 末尾槽位
        fieldType[fieldType.length - 1] = tmpFieldType[1];
        // 将类型从头存放到 fieldType
        for (int i = 0; i < fieldType.length - 1; i++) {
            fieldType[i] = tmpFieldType[0].substring(0, i);
        }
        return fieldType;
    }

    /**
     * 对某些符号进行相应替换
     */
    public static String replaceCharacter(String str) {
        return str.replace("/", ".");
    }

    /**
     * unicode编码文件名,以使编译前后文件名一致
     */
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
                    logger.error("An error occurred", e);
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
        int end;
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
            try {
                if (charStr.matches("[0-9a-fA-F]+")) {
                    int unicode = Integer.parseInt(charStr, 16); // 16进制转为int
                    if (Character.isValidCodePoint(unicode)) { // 检查是否为有效Unicode字符
                        letter = (char) unicode;
                    } else {
                        // 无效Unicode字符处理：将原始字符序列添加到buffer中
                        buffer.append("\\u").append(charStr);
                    }
                }else {
                    // 转换错误，将原始字符序列添加到buffer中
                    buffer.append("\\u").append(charStr);
                }
            } catch (Exception e) {
                // 转换错误，将原始字符序列添加到buffer中
                buffer.append("\\u").append(charStr);
            }
            buffer.append(letter);
            start = end;
        }
        return buffer.toString();
    }

    public static String reductionRelativePath(String path, String root) {
        String separator = "/|\\\\";
        String encodeRelativePath = path.substring(root.length() + 1);
        String[] names;
        names = encodeRelativePath.split(separator);                    //兼容windows和linux的分隔符
        StringBuilder relativePath = new StringBuilder();
        for (String name : names) {
            if (!name.isEmpty()) {
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

    /**
     * 参数: 文件路径、想过滤的字符串 . 输出: 该文件路径的文件名
     */
    public static String getFileNameByFilter(String filePath, String filter) {
        // 比如: filePath = "/demo/dao/impl/SQLIDaoImpl.class",filter为 "". 则输出结果为 SQLIDaoImpl.class
        File file = new File(filePath);
        return file.getName().replace(filter, "");
    }
    /** 从指定行进行删除  : 指定从某一行开始，后面全部置空。比如我输入的是45行，所以46行之后全部清除 ,保留前45行*/
    public static void deleteLinesAfter(String filePath, int specifiedLine) {
        try {
            // 读取原始文件内容
            BufferedReader bufferedReader = new BufferedReader(new FileReader(filePath));
            StringBuilder fileContent = new StringBuilder();
            String line;

            // 读取并保留指定行数之前的内容
            for (int i = 1; (line = bufferedReader.readLine()) != null && i <= specifiedLine; i++) {
                fileContent.append(line).append(System.lineSeparator());
            }
            bufferedReader.close();

            // 写入文件
            BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(filePath));
            bufferedWriter.write(fileContent.toString());
            bufferedWriter.close();

            System.out.println("Lines after line " + specifiedLine + " have been deleted.");

        } catch (IOException e) {
            logger.error("An error occurred", e);
        }
    }
    /** 根据文件名删除文件 */
    public static boolean deleteByFileName(String filePath){
        File fileToDelete = new File(filePath);
        return fileToDelete.delete();
    }

    /** 路径安全检查, 返回 true 就是不通过,被安全拦截**/
    public static boolean pathSecurityCheck(boolean operatingSystemModel,String content,String restrictingSuffixes){
        // 暂不考虑 mac ,因为我没 mac
        String pathRegex;
        if (operatingSystemModel) {
            pathRegex = String.format("%s%s$","^[a-zA-Z]:\\\\(?:[^\\\\/:*?\"<>|\\r ]+\\\\)*[^\\\\/:*?\"<>|\\r ]*",restrictingSuffixes); // Windows路径示例:    C:\2024.05.01.09.51.html
        } else {
            pathRegex = String.format("%s%s$","^/([^/]+/)*[^/]+",restrictingSuffixes);; // Linux路径示例:   /home/user/file.html
        }
        return !Pattern.matches(pathRegex, content);
    }
}

