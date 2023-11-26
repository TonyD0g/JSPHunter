package org.sec.ImitateJVM;

import java.lang.reflect.Field;

/** 利用反射修改asm分析出的AnalyzerAdapter中的变量 */
public class ChangeAsmVar {
    /**
     * 利用反射获取 操作数栈
     */
    public static Field getAsmStack(){
        try {
            Class<?> cls = Class.forName("org.objectweb.asm.commons.AnalyzerAdapter");
            Field stack = cls.getDeclaredField("stack");
            stack.setAccessible(true);
            return stack;
        } catch (ClassNotFoundException | NoSuchFieldException e) {
            throw new RuntimeException(e);
        }
    }

    /** 利用反射获取 局部变量表 */
    public static Field getAsmLocal(){
        try {
            Class<?> cls = Class.forName("org.objectweb.asm.commons.AnalyzerAdapter");
            Field locals = cls.getDeclaredField("locals");
            locals.setAccessible(true);
            return locals;
        } catch (ClassNotFoundException | NoSuchFieldException e) {
            throw new RuntimeException(e);
        }
    }
}
