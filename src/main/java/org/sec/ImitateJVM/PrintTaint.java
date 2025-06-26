package org.sec.ImitateJVM;

import java.util.*;

/**
 * 用于输出完整的污点传递流程
 */
public class PrintTaint<T> {
    public LinkedList<PrintTaint> PrintTaintStack = new LinkedList<>();

    public String owner;

    public String name;

    public String desc;

    public Set<T> stainIndex;

    public void push(PrintTaint t) {
        PrintTaintStack.add(t);
    }

    public void clear() {
        PrintTaintStack.clear();
    }

    // 删除一些会影响到【输出利用链】的不相关owner、name、desc
    private void deleteUnrelatedElement(){
        Iterator iterator = Constant.tempPrintTaint.PrintTaintStack.iterator();
        while (iterator.hasNext()) {
            PrintTaint printTaint = (PrintTaint) iterator.next();
            if(printTaint.owner.equals("javax/servlet/jsp/JspWriter") && printTaint.name.equals("getBufferSize") && printTaint.desc.equals("()I")){
                iterator.remove();
                continue;
            }
            if(printTaint.owner.equals("javax/servlet/http/HttpServletResponse") && printTaint.name.equals("isCommitted") && printTaint.desc.equals("()Z")){
                iterator.remove();
                continue;
            }
            if(printTaint.owner.equals("javax/servlet/jsp/JspWriter") && printTaint.name.equals("flush") && printTaint.desc.equals("()V")){
                iterator.remove();
                continue;
            }
            if(printTaint.owner.equals("javax/servlet/jsp/JspWriter") && printTaint.name.equals("clearBuffer") && printTaint.desc.equals("()V")){
                iterator.remove();
                continue;
            }
            if(printTaint.owner.equals("javax/servlet/jsp/PageContext") && printTaint.name.equals("handlePageException") && printTaint.desc.equals("(Ljava/lang/Throwable;)V")){
                iterator.remove();
                continue;
            }
            if(printTaint.owner.equals("javax/servlet/ServletException") && printTaint.name.equals("<init>") && printTaint.desc.equals("(Ljava/lang/Throwable;)V")){
                iterator.remove();
                continue;
            }
            if(printTaint.owner.equals("javax/servlet/jsp/JspFactory") && printTaint.name.equals("releasePageContext") && printTaint.desc.equals("(Ljavax/servlet/jsp/PageContext;)V")){
                iterator.remove();
            }
        }
    }

    // 输出当前的利用链
    public void printCurrentTaintStack(String stainType) {
        deleteUnrelatedElement();
        if (Constant.tempPrintTaint.PrintTaintStack.size() - 1 > 0) {
            String tempString;
            Constant.msgList.add(String.format("<br><span class=\"badge badge-warning\">[ %s ] 可能的利用链如下:<br>----------------------------------------------------------------</span>", stainType));
            for (int index = 0; index <= Constant.tempPrintTaint.PrintTaintStack.size() - 1; index++) {
                tempString = PrintTaintStack.get(index).stainIndex.toString();
                Constant.msgList.add(String.format("[ owner: %s , name: %s , desc: %s , stainIndex: %s ]\n",
                        PrintTaintStack.get(index).owner,
                        PrintTaintStack.get(index).name,
                        PrintTaintStack.get(index).desc,
                        tempString));
            }
            Constant.msgList.add("<span class=\"badge badge-warning\">----------------------------------------------------------------</span><br><br><br>");
            Constant.tempPrintTaint.clear();
        }
        if(DebugOption.userDebug && Constant.msgList.stream().anyMatch(str -> str.contains("可能的利用链如下"))){
            List<String> tempMsgList = Constant.resultInfo.getMsgList();
            tempMsgList.addAll(new ArrayList<>(Constant.msgList));
            Constant.resultInfo.setMsgList(tempMsgList);
            Constant.msgList.clear();
        }
    }
}
