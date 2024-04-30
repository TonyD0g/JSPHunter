package org.sec;

import org.apache.log4j.Logger;
import org.sec.Start.Application;

import java.io.IOException;

public class Main {
    private static final Logger logger = Logger.getLogger(Main.class);

    public static void main(String[] args) throws IOException, ClassNotFoundException {

        System.out.println("       _  _____ _____  _    _             _            \n" +
                "      | |/ ____|  __ \\| |  | |           | |           \n" +
                "      | | (___ | |__) | |__| |_   _ _ __ | |_ ___ _ __ \n" +
                "  _   | |\\___ \\|  ___/|  __  | | | | '_ \\| __/ _ \\ '__|\n" +
                " | |__| |____) | |    | |  | | |_| | | | | ||  __/ |   \n" +
                "  \\____/|_____/|_|    |_|  |_|\\__,_|_| |_|\\__\\___|_|");
        logger.info("start JSPHunter application");
        // 运行主逻辑
        Application.start(args);
        System.out.println("JSPHunter (Version:   1.8.0)  Modify from TonyD0g");
    }
}