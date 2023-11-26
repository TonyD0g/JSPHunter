package org.sec.Scan;

/** JSPHunter内置的污点源 */
public class stainSource {
    // 使用黑名单的方式去匹配 能外界输入的类,对应的方法,对应参数(0为主体,1~n为参数)
    public static final Object[][] PASSTHROUGH_DATAFLOW;
    static {
        // 内置污点源,为默认污点源
        PASSTHROUGH_DATAFLOW = new Object[][]{
                {"java/lang/Object", "toString", "()Ljava/lang/String;", 0},

                // Taint from ObjectInputStream. Note that defaultReadObject() is handled differently below
                {"java/io/ObjectInputStream", "readObject", "()Ljava/lang/Object;", 0},
                {"java/io/ObjectInputStream", "readFields", "()Ljava/io/ObjectInputStream$GetField;", 0},
                {"java/io/ObjectInputStream$GetField", "get", "(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;", 0},

                // Pass taint from class name to returned class
                {"java/lang/Object", "getClass", "()Ljava/lang/Class;", 0},
                {"java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;", 0},

                // Pass taint from class or method name to returned method
                {"java/lang/Class", "getMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", 0, 1},

                // Pass taint from class to methods
                {"java/lang/Class", "getMethods", "()[Ljava/lang/reflect/Method;", 0},
                {"java/lang/StringBuilder", "<init>", "(Ljava/lang/String;)V", 0, 1},
                {"java/lang/StringBuilder", "<init>", "(Ljava/lang/CharSequence;)V", 0, 1},
                {"java/lang/StringBuilder", "append", "(Ljava/lang/Object;)Ljava/lang/StringBuilder;", 0, 1},
                {"java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", 0, 1},
                {"java/lang/StringBuilder", "append", "(Ljava/lang/StringBuffer;)Ljava/lang/StringBuilder;", 0, 1},
                {"java/lang/StringBuilder", "append", "(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;", 0, 1},
                {"java/lang/StringBuilder", "append", "(Ljava/lang/CharSequence;II)Ljava/lang/StringBuilder;", 0, 1},
                {"java/lang/StringBuilder", "toString", "()Ljava/lang/String;", 0},

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

                // 自己添加的 *号表示匹配所有参数、返回类型的方法
                {"java/lang/String", "<init>", "*", 1},
                {"java/lang/String", "valueOf", "*", 0},
                {"sun/misc/BASE64Decoder", "decodeBuffer", "*", 1},
                {"sun/misc/BASE64Decoder", "decodeBufferToByteBuffer", "*", 1},
                {"java/util/Base64$Decoder", "decode", "*", 1},

                {"java/lang/Class", "getDeclaredMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", 0, 1},
                {"java/lang/Class", "getDeclaredMethods", "()[Ljava/lang/reflect/Method;", 0},
                {"java/lang/Class", "getDeclaredConstructors", "()[Ljava/lang/reflect/Constructor;", 0},
                {"java/lang/Class", "getDeclaredConstructor", "[Ljava/lang/Class;)Ljava/lang/reflect/Constructor;", 0, 1},
                {"java/lang/Class", "getConstructor", "([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;", 0, 1},
                {"java/lang/Class", "getConstructors", "()[Ljava/lang/reflect/Constructor;", 0},
                {"java/util/List", "add", "(Ljava/lang/Object;)Z", 1},
                {"java/lang/reflect/Constructor", "newInstance", "([Ljava/lang/Object;)Ljava/lang/Object;", 0, 1},
                {"java/lang/reflect/Method", "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", 0, 1, 2},
                {"java/lang/Process", "getInputStream", "()Ljava/io/InputStream;", 0},
                {"java/util/Scanner", "<init>", "(Ljava/io/InputStream;)V", 1},
                {"java/util/Scanner", "next", "()Ljava/lang/String;", 0},
                {"java/lang/String", "getBytes", "*", 0},
                {"sun/misc/BASE64Encoder", "encode", "*", 1},

                // gadgetinspector 跑出来的append方法污染点只有0号参数，显然是不对的，这里添加白名单
                {"java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", 0, 1},
                // 表示doFind()参数为空时候，没有污点
                {"javax/crypto/Cipher", "doFinal", "()[B", -1},
                {"javax/crypto/Cipher", "doFinal", "*", 1},
                {"java/io/BufferedReader", "readLine", "()Ljava/lang/String;", 0},
                {"javax/servlet/http/HttpServletRequest", "getInputStream", "()Ljavax/servlet/ServletInputStream;", 0},

                {"java/lang/ProcessBuilder", "command", "([Ljava/lang/String;)Ljava/lang/ProcessBuilder;", 1},

        };
    }
    public static Object[][] tmpPASSTHROUGH_DATAFLOW;
}
