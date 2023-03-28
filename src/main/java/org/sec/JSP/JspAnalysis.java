package org.sec.JSP;


import org.apache.jasper.JspC;

import java.util.ArrayList;

public class JspAnalysis {
    /** 利用 jasper 编译 java 文件为 jsp 文件 */
    public static void jasper(String webDir,String classPath,String file,ArrayList<String> jspFilePathList){
        for (String jspFilePath : jspFilePathList) {
            try {
                // 设置一些编译环境
                JspC jspc = new JspC();
                jspc.setCompile(true);
                jspc.setClassDebugInfo(false);
                jspc.setUriroot(webDir);
                jspc.setCompilerTargetVM("1.8");
                jspc.setCompilerSourceVM("1.8");
                jspc.setOutputDir("JspCompile");
                jspc.setClassPath(classPath);
                if (file != null) {
                    jspc.setJspFiles(file);
                } else {
                    jspc.setJspFiles(jspFilePath);
                }
                jspc.execute();
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }
    }
}
