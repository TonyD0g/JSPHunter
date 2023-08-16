package org.sec;

import org.apache.log4j.Logger;
import org.sec.input.Logo;
import org.sec.start.Application;

import java.io.IOException;

public class Main {
    private static final Logger logger = Logger.getLogger(Main.class);

    public static void main(String[] args) throws IOException, ClassNotFoundException {

        Logo.PrintLogo();
        logger.info("start JSPHunter application");
        // 运行主逻辑
        Application.start(args);
        System.out.println("JSPHunter (Version:   0.1.6)  Modify from TonyD0g");
    }
}