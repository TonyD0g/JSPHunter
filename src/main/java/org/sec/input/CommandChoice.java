package org.sec.input;

import com.beust.jcommander.JCommander;

/** [+] 根据命令自定义选项*/
public abstract class CommandChoice{
    public static boolean CommandChoice(Command command, JCommander jc) {
        if (command.help) {
            jc.usage();
            return true;
        }
        if (command.output == null || command.output.equals("")) {
            command.output = "result.jsp"; // [+]
            return true;
        }
        return false;
    }
}
