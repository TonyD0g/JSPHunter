package org.sec.utils;

import org.apache.log4j.Logger;

import java.util.Scanner;

/** input工具类 */
public class InputUtils {
    public static Scanner input = new Scanner(System.in);
    private static final Logger logger = Logger.getLogger(InputUtils.class);

    /** 输入命令 */
    public String inputCmd() {
        logger.info("[+] Please input the cmd");
        String cmd;
        while ((cmd = input.nextLine()) == null) {
            logger.info("[-] Please reInput the cmd");
            input.nextLine();
        }
        return cmd;
    }
}
