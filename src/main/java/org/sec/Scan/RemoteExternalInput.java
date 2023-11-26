package org.sec.Scan;

/** 远程的外部输入 **/
public class RemoteExternalInput {
    public static final Object[][] PASSTHROUGH_DATAFLOW;
    static {
        PASSTHROUGH_DATAFLOW = new Object[][]{
                // Taint from ObjectInputStream. Note that defaultReadObject() is handled differently below
                {"java/io/ObjectInputStream", "readObject", "()Ljava/lang/Object;", 0},
                {"java/io/ObjectInputStream", "readFields", "()Ljava/io/ObjectInputStream$GetField;", 0},
                {"java/io/ObjectInputStream$GetField", "get", "(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;", 0},

                {"java/io/ByteArrayInputStream", "<init>", "([B)V", 1},
                {"java/io/ByteArrayInputStream", "<init>", "([BII)V", 1},
                {"java/io/ObjectInputStream", "<init>", "(Ljava/io/InputStream;)V", 1},
                {"java/io/File", "<init>", "(Ljava/lang/String;I)V", 1},
                {"java/io/File", "<init>", "(Ljava/lang/String;Ljava/io/File;)V", 1},
                {"java/io/File", "<init>", "(Ljava/lang/String;)V", 1},
                {"java/io/File", "<init>", "(Ljava/lang/String;Ljava/lang/String;)V", 1},

                {"java/nio/paths/Paths", "get", "(Ljava/lang/String;[Ljava/lang/String;)Ljava/nio/file/Path;", 0},

                {"java/net/URL", "<init>", "(Ljava/lang/String;)V", 1},

                {"javax/servlet/http/HttpServletRequest", "getParameter", "(Ljava/lang/String;)Ljava/lang/String;", 0},
                {"javax/servlet/http/HttpServletRequest", "getQueryString", "()Ljava/lang/String;", 0},
                {"javax/servlet/http/HttpServletRequest", "getParameterNames", "()Ljava/util/Enumeration;", 0},
                {"javax/servlet/http/HttpServletRequest", "getParameterValues", "(Ljava/lang/String;)[Ljava/lang/String;", 0},
                {"javax/servlet/http/HttpServletRequest", "getParameterMap", "()Ljava/util/Map;", 0},
                {"javax/servlet/http/HttpServletRequest", "getHeader", "(Ljava/lang/String;)Ljava/lang/String;", 0},
                {"javax/servlet/http/HttpServletRequest", "getHeaders", "(Ljava/lang/String;)Ljava/util/Enumeration;", 0},
                {"javax/servlet/http/HttpServletRequest", "getHeaderNames", "()Ljava/util/Enumeration;", 0},
                {"javax/servlet/http/HttpServletRequest", "getReader", "()Ljava/io/BufferedReader;", 0},

                // gadgetinspector默认查找的是反序列化的链，它认为每个方法的0参对象都是可以被控制的，但查找sql注入不一样，对于部分构造方法，需要自己明确哪个参数可以污染，要不然污点分析走不下去
                {"org/springframework/jdbc/core/JdbcTemplate$1QueryStatementCallback", "<init>", "(Lorg/springframework/jdbc/core/JdbcTemplate;Ljava/lang/String;Lorg/springframework/jdbc/core/ResultSetExtractor;)V", 2},

                {"java/lang/Process", "getInputStream", "()Ljava/io/InputStream;", 0},
                {"java/util/Scanner", "<init>", "(Ljava/io/InputStream;)V", 1},
                {"java/util/Scanner", "next", "()Ljava/lang/String;", 0},
                {"javax/servlet/http/HttpServletRequest", "getInputStream", "()Ljavax/servlet/ServletInputStream;", 0},
        };
    }
}
