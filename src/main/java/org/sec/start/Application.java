package org.sec.start;

import com.beust.jcommander.JCommander;
import org.apache.log4j.Logger;
import org.sec.JSP.JspAnalysis;
import org.sec.input.Command;
import org.sec.input.CommandChoice;
import org.sec.utils.FileUtils;

import java.io.File;
import java.io.IOException;
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
        if(command.dict != null){
            // 获取webDir目录下的所有文件，并放置在一个hashSet中
            Set<String> fileArray = new HashSet<>();
            FileUtils.readWebDir(command.dict, fileArray);

            // TODO 依次编译java文件,使用 jasper
            for (String file : fileArray) {
                // TODO 清除之前的环境,和 获取jsp目录文件,以便后续解析

                FileUtils.flushDir("JspCompile");
                ArrayList<String> jspFilePathList = new ArrayList<>();
                FileUtils.getAnyFilePath(file, jspFilePathList);
                ArrayList<String> jarFilePath = new ArrayList<>();
                String classPath = "";
                if (command.classPath != null) {
                    FileUtils.getAnyFilePath(command.classPath, jarFilePath);
                    for (String jarFileName : jarFilePath) {
                        classPath = classPath + File.pathSeparator + jarFileName;
                    }
                }
                // 使用 jasper 解析
                JspAnalysis.jasper(file,classPath,Command.file,jspFilePathList);


                //删除编译文件
                FileUtils.delete(new File("JspCompile"));
            }

            String module = command.module;
            switch (module){
                case "b":
                    Application.logger.info("[+] Use Basic Analyse");
                    //basic(command);
                    break;
                case "e":
                    Application.logger.info("[+] Use Extend Analyse");
                    //Extend(command);
                    break;
            }
        }
        else {
            Application.logger.info("[-] the dict isn't exist,please check correct!");
        }

        return false;
    }
}
