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

    @Parameter(names = {"-m", "--module"}, description = "Scan Module")
    public String module;

    @Parameter(names = {"-cp", "--classpath"}, description = "指定容器的依赖jar包(tomcat例为:D:\\apache-tomcat-8.0.50\\lib)")
    public String classPath;

    @Parameter(names = {"-f", "--file"}, description = "指定web目录下的某个文件")
    public String file;
}
