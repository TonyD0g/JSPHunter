package org.sec.ImitateJVM;

import java.util.ArrayList;
import java.util.Arrays;

/**
 * debug选项，开启后能方便调试
 */
public class DebugOption {
    // 是否开启debug选项: userDebug为方便用户查看,systemDebug为方便开发人员查看
    public static boolean systemDebug = false;
    public static boolean userDebug = false;

    // 记录压栈了几次
    public static int pushNum = 0;

    // 记录哪个字节码造成了压栈，
    public static ArrayList<Integer> whoOpcodes = new ArrayList<>();

    public static String owner = new String();
    public static String name = new String();
    public static String desc = new String();

    /**
     * 恢复为初始值(除了debug选项)
     */
    public static void clearSet() {
        pushNum = 0;
        whoOpcodes.clear();
    }

    /**
     * 记录debug选项
     */
    public static void setDebug(int opcode) {
        if(systemDebug == false){
            return;
        }
        whoOpcodes.set(pushNum, opcode);
        pushNum++;
    }

    /** 设置过滤器,方便于调试 */
    public static void setFilter(String owner1,String name1, String desc1){
        owner = owner1;
        name = name1;
        desc = desc1;
    }
    /** 执行过滤 */
    public static void filter(String owner1,String name1, String desc1){
        if (owner.equals(owner1) &&  name.equals(name1) && desc.equals(desc1)){
            printDebug();
        }
    }

    /**
     * 输出debug选项到控制台
     */
    public static void printDebug() {
        // 如果根本就没压栈,则直接退出不打印
        if(whoOpcodes.get(0) == 0){
            return;
        }
        System.out.println("----------------------------------------------------------------");
        System.out.println(String.format("[ %s , %s , %s ]",owner,name,desc));
        for (int i = 0; i < whoOpcodes.size() - 1; i++) {
            if(whoOpcodes.get(i) == 0){
                break;
            }
            System.out.println("opcode composition: " + whoOpcodes.get(i));
        }
        System.out.println("----------------------------------------------------------------");
    }

}
