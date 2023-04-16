package org.sec.ImitateJVM;

// [-] 没用,待删除
/** dup强引用 */
public class DupStrongConnection {

    public int indexOfBody; // 1.被复制的本体在操作数栈中的index

    public int indexOfCopy; // 2.复制体在操作数栈中的index

    public boolean isAffectBody; // 3.此函数是否影响本体
}
