package org.sec.JSP;

import org.apache.jasper.JspC;
import org.apache.log4j.Logger;

import java.util.ArrayList;

public class JspAnalysis {
    private static final Logger logger = Logger.getLogger(JspAnalysis.class);
    /**
     * 利用 jasper 编译 java 文件为 jsp 文件
     */
    public static void jasper(String webDir, String classPath, String file, ArrayList<String> jspFilePathList) {
        int flag = 0;
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
                    flag = 1;
                }
                jspc.execute();
                flag = 0;
            } catch (Exception e) {
                if(flag == 0){
                    logger.info("[-] The jsp file is error! : " + file);
                }else{
                    logger.info("[-] The jsp file is error! : " + jspFilePath);
                }
            }
        }
        System.out.println("\n---------------------------------------------------------------------------\nScan begin:\n");
    }
}
