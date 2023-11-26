package org.sec.utils.ArrayUtils;

import java.util.Arrays;

/**
 * [+] 动态数组
 */
public abstract class DynamicArray {
    private int size;    //表示当前动态数组中已经存储的元素个数
    public int recordZero;    // 记录 下标为0的 个数
    public int[] recordIndex;    // 记录 要添加特殊字符时的下标
    public int[] intChar;    // 记录 ascii对应的数字
    public char[] specialAscii;    // 记录 ascii

    public ArrayList[] array;

    public DynamicArray() {
        //默认开辟10个大小的整形数组长度
    }

    public DynamicArray(int initCap) {//传入一个整型变量
        this.array = new ArrayList[initCap];
    }

    /**
     * 添加新元素val(customizeArray)
     */
    public void addCustomize(ArrayList[] customizeArray, ArrayList val) {
        customizeArray[size] = val;
        size++;
        /*元素在添加的过程中有可能把当前数组占满了
        当size=data.length数组已满 */
        if (size == array.length) {
            growCustomize(customizeArray);
        }
    }

    /**
     * 添加新元素val(int)
     */
    public void addInt(int[] intArray, int val) {
        intArray[size] = val;
        size++;
        /*元素在添加的过程中有可能把当前数组占满了
        当size=data.length数组已满 */
        if (size == intArray.length) {
            intArray = growInt(intArray);
        }
    }

    /**
     * 添加新元素val(float)
     */
    public void addFloat(float[] floatArray, float val) {
        floatArray[size] = val;
        size++;
        /*元素在添加的过程中有可能把当前数组占满了
        当size=data.length数组已满 */
        if (size == floatArray.length) {
            growFloat(floatArray);
        }
    }

    /**
     * 添加新元素val(double)
     */
    public void addDouble(double[] doubleArray, double val) {
        doubleArray[size] = val;
        size++;
        /*元素在添加的过程中有可能把当前数组占满了
        当size=data.length数组已满 */
        if (size == doubleArray.length) {
            growDouble(doubleArray);
        }
    }

    /**
     * 添加新元素val(String)
     */
    public void addString(String[] stringArray, String val) {
        stringArray[size] = val;
        size++;
        /*元素在添加的过程中有可能把当前数组占满了
        当size=data.length数组已满 */
        if (size == stringArray.length) {
            growString(stringArray);
        }
    }

    /**
     * 添加新元素val(Char)
     */
    public void addChar(char[] charArray, char val) {
        charArray[size] = val;
        size++;
        /*元素在添加的过程中有可能把当前数组占满了
        当size=data.length数组已满 */
        if (size == charArray.length) {
            growChar(charArray);
        }
    }

    /**
     * 执行数组扩容方法(Customize)
     */
    private ArrayList[] growCustomize(ArrayList[] customizeArray) {
        //copy of方法返回扩容后的新数组
        return Arrays.copyOf(customizeArray, customizeArray.length * 2);
    }

    /**
     * 执行数组扩容方法(Customize)
     */
    private int[] growInt(int[] intArray) {
        //copy of方法返回扩容后的新数组
        return Arrays.copyOf(intArray, intArray.length * 2);
    }

    /**
     * 执行数组扩容方法(Customize)
     */
    private double[] growDouble(double[] doubleArray) {
        //copy of方法返回扩容后的新数组
        return Arrays.copyOf(doubleArray, doubleArray.length * 2);
    }

    /**
     * 执行数组扩容方法(Customize)
     */
    private float[] growFloat(float[] floatArray) {
        //copy of方法返回扩容后的新数组
        return Arrays.copyOf(floatArray, floatArray.length * 2);
    }

    /**
     * 执行数组扩容方法(Customize)
     */
    private char[] growChar(char[] charArray) {
        //copy of方法返回扩容后的新数组
        return Arrays.copyOf(charArray, charArray.length * 2);
    }

    private String[] growString(String[] stringArray) {
        //copy of方法返回扩容后的新数组
        return Arrays.copyOf(stringArray, stringArray.length * 2);
    }
}
