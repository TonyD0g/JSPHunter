package org.sec.ImitateJVM;

import org.sec.Constant.Constant;

import java.util.LinkedList;
import java.util.Set;

/**
 * 用于输出完整的污点传递流程
 */
public class PrintTaint<T> {
    private final LinkedList<PrintTaint<T>> PrintTaintStack = new LinkedList<>();

    public String owner;

    public String name;

    public String desc;

    public Set<T> stainIndex;

    public void push(PrintTaint<T> t) {
        Constant.currentPrintTaint.PrintTaintStack.add(t);
    }

    public void clear() {
        Constant.currentPrintTaint.PrintTaintStack.clear();
    }

    // 输出当前的利用链
    public void printCurrentTaintStack(String stainType) {
        String tempString;
        System.out.printf("[ %s ] 完整的利用链如下:\n----------------------------------------------------------------\n",stainType);
        for (int index = Constant.currentPrintTaint.PrintTaintStack.size(); index > 0; index--) {
            tempString = PrintTaintStack.get(index - 1).stainIndex.toString();
            if(tempString.equals("[]")){
                continue;
            }
            System.out.printf("[ owner: %s , name: %s , desc: %s , stainIndex: %s ]\n",
                    PrintTaintStack.get(index - 1).owner,
                    PrintTaintStack.get(index - 1).name,
                    PrintTaintStack.get(index - 1).desc,
                    tempString
            );
        }
        System.out.println("----------------------------------------------------------------\n\n\n");
        Constant.currentPrintTaint.clear();
    }
}
