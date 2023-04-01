package org.sec.start;

import com.beust.jcommander.JCommander;
import org.apache.log4j.Logger;
import org.sec.Constant.Constant;
import org.sec.JSP.JspAnalysis;
import org.sec.Main;
import org.sec.input.Command;
import org.sec.input.CommandChoice;
import org.sec.utils.FileUtils;
import org.sec.utils.stringUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

public class Application {
    public static final Logger logger = Logger.getLogger(Application.class);

    public static void start(String[] args) {
        Command command = new Command();
        JCommander jc = JCommander.newBuilder().addObject(command).build();
        jc.parse(args);

        CommandChoiceTest commandChoiceTest = new CommandChoiceTest(command, jc);
        if (commandChoiceTest.commandChoiceOverWrite(command, jc)) {
            logger.info("[-] Don't have this choice,Please repeat to choice!");
        }
    }

}

class CommandChoiceTest extends CommandChoice {
    private static final Logger logger = Logger.getLogger(CommandChoiceTest.class);

    public CommandChoiceTest(Command command, JCommander jc) {
        super();
    }

    /**
     * [+] 重写 命令选择
     */
    public boolean commandChoiceOverWrite(Command command, JCommander jc) {
        // 判断是否存在该命令
        if (CommandChoice.CommandChoice(command, jc)) {
            return false;
        }
        String module = command.module;
        switch (module) {
            // 基础分析
            case "b":
                Application.logger.info("[+] Use Basic Analyse");
                Analysis(command,jc);
                //basic(command);
                break;
            // 可疑分析
            case "e":
                Application.logger.info("[+] Use Extend Analyse");
                Analysis(command,jc);
                //suspicious(command);
                break;
        }

        return false;
    }
    public static void Analysis(Command command, JCommander jc){
        if (command.dict != null) {
            // 获取webDir目录下的所有文件，并放置在一个hashSet中
            Set<String> fileArray = new HashSet<>();
            FileUtils.readWebDir(command.dict, fileArray);

            for (String filePath : fileArray) {
                // 清除之前的环境,和 获取jsp目录文件,以便后续解析
                //passthroughDataflow 可以不用清除，passthroughDataflow 清了要重新从磁盘读取一份，消耗资源，就算保留之前被分析的类的污染关系也无所谓，因为一般不会出现类名相同、方法名相同但方法内容不通的情况
                Constant.evilClass.clear();
                Constant.classNameToJspName.clear();
                Constant.sortedMethodCalls.clear();
                Constant.classFileNameToByte.clear();

                FileUtils.flushDir("JspCompile");
                ArrayList<String> jspFilePathList = new ArrayList<>();
                FileUtils.getWantSuffixFilePath(filePath, "jsp", jspFilePathList);
                ArrayList<String> jarFilePath = new ArrayList<>();
                String classPath = "";
                if (command.classPath != null) {
                    FileUtils.getWantSuffixFilePath(command.classPath, "jar", jarFilePath);
                    for (String jarFileName : jarFilePath) {
                        classPath = classPath + File.pathSeparator + jarFileName;
                    }
                }
                // 使用 jasper 解析
                JspAnalysis.jasper(filePath, classPath, Command.file, jspFilePathList);

                ArrayList<String> classFileNameList = new ArrayList<String>();
                FileUtils.getWantSuffixFilePath("JspCompile", "class", classFileNameList);

                logger.info("开始扫描" + filePath);
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
                    String webJspName = (filePath.substring(filePath.length() - 1).equals(File.separator) ? filePath : filePath + File.separator) + relativeJspName;
                    Constant.classNameToJspName.put(classFileName, webJspName);
                }

//                PassthroughDiscovery passthroughDiscovery = new PassthroughDiscovery();
//                passthroughDiscovery.discover();
//                FindEvilDiscovery findEvilDiscovery = new FindEvilDiscovery();
//                findEvilDiscovery.discover();
                logger.info(filePath + "扫描结束");
                System.out.println("\r\n");

                //删除编译文件
                FileUtils.delete(new File("JspCompile"));
            }
        } else {
            Application.logger.info("[-] the dict isn't exist,please check correct!");
        }
    }
}
