package org.sec.start;

import com.beust.jcommander.JCommander;
import org.apache.log4j.Logger;
import org.sec.input.Command;
import org.sec.input.CommandChoice;

import java.io.IOException;

public class Application {
    private static final Logger logger = Logger.getLogger(Application.class);

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
        if (CommandChoice.CommandChoice(command, jc)) {
            return false;
        }
        // [+]
        // 示例代码:
//        if (command.javacModule) {
//            logger.info("[-] use javac module");
//            doJavac(command); // 符合命令就进入相应的方法
//            return true;
//        }
        return false;
    }
}
