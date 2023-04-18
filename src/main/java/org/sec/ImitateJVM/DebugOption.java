package org.sec.ImitateJVM;

import java.util.Arrays;

/**
 * debug选项，开启后能方便调试
 */
public class DebugOption {
    // 是否开启debug选项
    public static boolean debug = false;

    // 记录压栈了几次
    public static int pushNum = 0;

    // 记录哪个字节码造成了压栈，
    public static int[] whoOpcodes = new int[50]; // 先假定最多20个

    public static String owner = new String();
    public static String name = new String();
    public static String desc = new String();

    /**
     * 恢复为初始值(除了debug选项)
     */
    public static void clearSet() {
        pushNum = 0;
        Arrays.fill(whoOpcodes, 0);
    }

    /**
     * 记录debug选项
     */
    public static void setDebug(int opcode) {
        whoOpcodes[pushNum] = opcode;
        pushNum++;
    }

    /** 设置主体 */
    public static void setOwner(String owner1,String name1, String desc1){
        owner = owner1;
        name = name1;
        desc = desc1;
    }

    /**
     * 输出debug选项到控制台
     */
    public static void printDebug() {
        if(whoOpcodes[0] == 0){
            return;
        }
        System.out.println("----------------------------------------------------------------");
        System.out.println(String.format("[ %s , %s , %s ]",owner,name,desc));
        for (int i = 0; i < whoOpcodes.length - 1; i++) {
            if(whoOpcodes[i] == 0){
                break;
            }
            System.out.println("opcode composition: " + whoOpcodes[i]);
        }
        System.out.println("----------------------------------------------------------------");
    }

    // todo 设置过滤器
    public static void test(String owner1,String name1, String desc1){

    }
}
