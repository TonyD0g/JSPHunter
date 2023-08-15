package org.sec.input;

import com.beust.jcommander.Parameter;
/** [+] 处理用户输入的参数 */
public  class Command {
    @Parameter(names = {"-h", "--help"}, description = "Help Info", help = true)
    public boolean help;

    @Parameter(names = {"-o", "--output"}, description = "Output File")
    public String output;

    @Parameter(names = {"-d", "--dict"}, description = "Webshell Dict")
    public String dict;

    @Parameter(names = {"-del", "--delete"}, description = "delete shell")
    public boolean delete;

    @Parameter(names = {"-cp", "--classpath"}, description = "指定容器的依赖jar包(tomcat例为:D:\\apache-tomcat-8.0.50\\lib)")
    public String classPath;

    @Parameter(names = {"-f", "--file"}, description = "指定web目录下的某个文件")
    public String file;

    @Parameter(names = {"-debug", "--debug"}, description = "开启debug选项(用户层)")
    public boolean debug;

    @Parameter(names = {"-info", "--info"}, description = "尝试获取单个shell的信息,方便分析,注意是单个,不然得出的顺序有误,会影响分析结果!")
    public boolean info;
}
