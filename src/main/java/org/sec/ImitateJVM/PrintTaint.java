package org.sec.ImitateJVM;

import org.sec.Constant.Constant;

import java.util.LinkedList;
import java.util.Set;

/**
 * 用于输出完整的污点传递流程
 */
public class PrintTaint<T> {
    public LinkedList<PrintTaint> PrintTaintStack = new LinkedList<>();

    public String owner;

    public String name;

    public String desc;

    public Set<T> stainIndex;

    public boolean hasReturn = false;

    public void push(PrintTaint t) {
        PrintTaintStack.add(t);
    }

    public void clear() {
        PrintTaintStack.clear();
    }

    // 输出当前的利用链
    public void printCurrentTaintStack(String stainType) {
        if(Constant.tempPrintTaint.PrintTaintStack.size() - 1 > 0){
            String tempString;
            System.out.printf("[ %s ] 完整的利用链如下:\n----------------------------------------------------------------\n", stainType);
            for (int index = 0; index < Constant.tempPrintTaint.PrintTaintStack.size() - 1; index++) {
                tempString = PrintTaintStack.get(index).stainIndex.toString();
                System.out.printf("[ owner: %s , name: %s , desc: %s , stainIndex: %s ]\n",
                        PrintTaintStack.get(index).owner,
                        PrintTaintStack.get(index).name,
                        PrintTaintStack.get(index).desc,
                        tempString
                );
            }
            System.out.println("----------------------------------------------------------------\n\n\n");
            Constant.tempPrintTaint.clear();
        }
    }
}
