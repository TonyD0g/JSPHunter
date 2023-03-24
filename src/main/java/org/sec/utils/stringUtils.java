package org.sec.utils;

public class stringUtils {
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
}

