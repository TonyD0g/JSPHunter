package org.sec.start;

import org.sec.Form.JSPHunter;
import org.sec.ImitateJVM.Constant;
import org.sec.JSP.JspAnalysis;
import org.sec.Scan.FindEvilDiscovery;
import org.sec.Scan.PassthroughDiscovery;
import org.sec.Scan.getAllString;
import org.sec.Scan.stainSource;
import org.sec.Utils.FileUtils;
import org.sec.Utils.Render.ResultOutput;
import org.sec.Utils.stringUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.*;

public class Application {
    public static void analysis() throws IOException, ClassNotFoundException {
        // todo bug, 需要解决当jsp文件名有中文时就会出bug,会无法分析，猜测原因在不能一一对应上
        // 获取webDir目录下的所有文件，并放置在一个hashSet中
        Set<String> fileArray = new HashSet<>();
        FileUtils.readWebDir(Constant.dict, fileArray);
        Constant.suspiciousNum = 0;
        Constant.maliceNum = 0;
        // 开始遍历扫描目录下的文件
        for (String webDir : fileArray) {
            // 清除之前的环境,和 获取jsp目录文件,以便后续解析
            clear();

            if (!FileUtils.flushDir("JspCompile")) {
                return;
            }
            ArrayList<String> jspFilePathList = new ArrayList<>();
            FileUtils.getWantSuffixFilePath(webDir, "jsp", jspFilePathList);
            ArrayList<String> jarFilePath = new ArrayList<>();
            StringBuilder classPath = new StringBuilder();
            if (Constant.classPath != null) {
                FileUtils.getWantSuffixFilePath(Constant.classPath, "jar", jarFilePath);
                for (String jarFileName : jarFilePath) {
                    classPath.append(File.pathSeparator).append(jarFileName);
                }
            }
            // 使用 jasper 去编译
            JspAnalysis.jasper(webDir, classPath.toString(), "", jspFilePathList);

            ArrayList<String> classFileNameList = new ArrayList<>();
            FileUtils.getWantSuffixFilePath("JspCompile", "class", classFileNameList);
            //Constant.msgList.add("[+] 开始扫描,扫描路径为:"+webDir + "\n---------------------------------------------------------------------------\n");
            for (String classFileName : classFileNameList) {
                //形成class文件和byte[]文件内容的对应
                byte[] classData = FileUtils.readBytes(String.valueOf(Paths.get(classFileName)));
                Constant.classFileNameToByte.put(classFileName, classData);

                //形成类名和byte[]文件内容的对应
                int endPoint = classFileName.indexOf(".class");
                int startPoint = classFileName.lastIndexOf(File.separator);
                Constant.classNameToByte.put(classFileName.substring(startPoint + 1, endPoint), classData);
                Constant.classNameToClassFileName.put(classFileName.substring(startPoint + 1, endPoint), classFileName);

                // 形成class文件和被扫描的jsp之间的对应
                String rootPath = new File("JspCompile").getAbsolutePath() + File.separator + "org" + File.separator + "apache" + File.separator + "jsp";
                String relativeJspClassName = stringUtils.reductionRelativePath(classFileName, rootPath);
                String relativeJspName = relativeJspClassName.substring(0, relativeJspClassName.lastIndexOf("."));

                // webJspName 为对应在web服务器上jsp文件的位置
                String webJspName = (webDir.substring(webDir.length() - 1).equals(File.separator) ? webDir : webDir + File.separator) + relativeJspName;
                Constant.classNameToJspName.put(classFileName, webJspName);
                Constant.classFileNameToIsLock.put(classFileName,true);
            }
            stainSource.getStainSource(stainSource.PASSTHROUGH_DATAFLOW);

            // 对方法进行dfs和逆排序
            PassthroughDiscovery passthroughDiscovery = new PassthroughDiscovery();
            passthroughDiscovery.discover();
            // 扫描是否存在恶意利用链
            FindEvilDiscovery findEvilDiscovery = new FindEvilDiscovery();
            findEvilDiscovery.findEvilDataflow(Constant.isOpenDeleteMode);
            // todo 加入到html界面
            FileUtils.writeLine(Constant.outputPath, "       _  _____ _____  _    _             _            \n" +
                    "      | |/ ____|  __ \\| |  | |           | |           \n" +
                    "      | | (___ | |__) | |__| |_   _ _ __ | |_ ___ _ __ \n" +
                    "  _   | |\\___ \\|  ___/|  __  | | | | '_ \\| __/ _ \\ '__|\n" +
                    " | |__| |____) | |    | |  | | |_| | | | | ||  __/ |   \n" +
                    "  \\____/|_____/|_|    |_|  |_|\\__,_|_| |_|\\__\\___|_|"+
                    "\n[+] 检测出的恶意文件数量: " + Constant.maliceNum + "\t 可疑文件数量: " + Constant.suspiciousNum, true);
            if (!Constant.compileErrorFileNameList.isEmpty()) {
                List<String> lines = new ArrayList<>();
                for (Map.Entry<Integer, String> entry : Constant.compileErrorFileNameList.entrySet()) {
                    lines.add(entry.getValue());
                }
                lines.add("[-] jasper编译失败的文件:\n");
                FileUtils.writeLines(Constant.outputPath, lines, true);
                lines.add("\n---------------------------------------------------------------------------\n" + "[+] 扫描结束\n");
            }
            FileUtils.writeLines(Constant.outputPath, Constant.msgList, true);
            ResultOutput.write(Constant.outputPath,Constant.results);
            FileUtils.delete(new File("JspCompile")); //删除编译文件
        }
        JSPHunter.openOutput(Constant.outputPath);
    }

    public static void clear(){
        //passthroughDataflow 可以不用清除，passthroughDataflow 清了要重新从磁盘读取一份，消耗资源，就算保留之前被分析的类的污染关系也无所谓，因为一般不会出现类名相同、方法名相同但方法内容不通的情况
        Constant.evilClass.clear();
        Constant.classNameToJspName.clear();
        Constant.sortedMethodCalls.clear();
        Constant.classFileNameToByte.clear();
        Constant.results.clear();
    }
}
