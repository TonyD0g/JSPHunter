package org.sec.ImitateJVM;

import org.apache.log4j.Logger;
import org.objectweb.asm.*;
import org.objectweb.asm.commons.AnalyzerAdapter;
//import org.sec.Scan.HandleAnonymousClass;
import org.sec.utils.stringUtils;

import java.lang.reflect.Field;
import java.util.*;

/**
 * 模拟栈帧的核心方法
 */
@SuppressWarnings("all")
public class CoreMethodAdapter<T> extends MethodVisitor {
    public static boolean isTest = false;
    public static String token = "";
    private static final Logger logger = Logger.getLogger(CoreMethodAdapter.class);
    private final AnalyzerAdapter analyzerAdapter;
    private final int access;
    protected final String name;
    private final String desc;
    public final String signature;
    public final String[] exceptions;

    private final Map<Label, GotoState<T>> gotoStates = new HashMap<>();
    private final Set<Label> exceptionHandlerLabels = new HashSet<>();

    public OperandStack<T> operandStack;
    public LocalVariables<T> localVariables;

    // 使用白名单的方式去匹配 能外界输入的类及其方法
    private static final Object[][] PASSTHROUGH_DATAFLOW;

    // todo 将此白名单导出到一个文件中,使用fileUtils去读取,方便于扩展
    static {
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

    // dup强引用
    DebugOption debugOption = new DebugOption();

    public CoreMethodAdapter(final int api, final MethodVisitor mv, final String owner, int access,
                             String name, String desc, String signature, String[] exceptions) {
        // AnalyzerAdapter 的特点是“可以模拟frame的变化”，或者说“可以模拟local variables和operand stack的变化”
        super(api, new AnalyzerAdapter(owner, access, name, desc, mv));
        this.analyzerAdapter = (AnalyzerAdapter) this.mv;
        this.access = access;
        this.name = name;
        this.desc = desc;
        this.signature = signature;
        this.exceptions = exceptions;
        operandStack = new OperandStack<>();
        localVariables = new LocalVariables<>();
    }

    protected void setLocalTaint(int index, T... possibleValues) {
        Set<T> values = new HashSet<T>();
        for (T value : possibleValues) {
            values.add(value);
        }
        localVariables.set(index, values);
    }

    /**
     * 校验栈帧,如果不符合规范，则直接终结进程
     */
    private void sanityCheck() {
        if (analyzerAdapter.stack != null && operandStack.size() != analyzerAdapter.stack.size()) {
            throw new IllegalStateException("bad stack size");
        }
    }

    /**
     * 控制跳转
     */
    private void mergeGotoState(Label label) {
        if (gotoStates.containsKey(label)) {
            GotoState<T> state = gotoStates.get(label);
            // old -> label
            LocalVariables<T> oldLocalVariables = state.getLocalVariables();
            OperandStack<T> oldOperandStack = state.getOperandStack();

            // new -> null
            LocalVariables<T> newLocalVariables = new LocalVariables<>();
            OperandStack<T> newOperandStack = new OperandStack<>();

            // init new,将旧的label迁移到新地方
            for (Set<T> original : oldLocalVariables.getList()) {
                newLocalVariables.add(new HashSet<>(original));
            }
            for (Set<T> original : oldOperandStack.getList()) {
                newOperandStack.add(new HashSet<>(original));
            }

            // add current state (?)
            for (int i = 0; i < newLocalVariables.size(); i++) {
                while (i >= oldLocalVariables.size()) {
                    oldLocalVariables.add(new HashSet<>());
                }
                newLocalVariables.get(i).addAll(oldLocalVariables.get(i));
            }
            for (int i = 0; i < newOperandStack.size(); i++) {
                while (i >= oldOperandStack.size()) {
                    oldOperandStack.add(new HashSet<>());
                }
                oldOperandStack.get(i).addAll(oldOperandStack.get(i));
            }

            // set new state
            GotoState<T> newGotoState = new GotoState<>();
            newGotoState.setOperandStack(newOperandStack);
            newGotoState.setLocalVariables(newLocalVariables);
            gotoStates.put(label, newGotoState);
        } else {
            LocalVariables<T> oldLocalVariables = localVariables;
            OperandStack<T> oldOperandStack = operandStack;
            // new -> null
            LocalVariables<T> newLocalVariables = new LocalVariables<>();
            OperandStack<T> newOperandStack = new OperandStack<>();

            // init new
            for (Set<T> original : oldLocalVariables.getList()) {
                newLocalVariables.add(new HashSet<>(original));
            }
            for (Set<T> original : oldOperandStack.getList()) {
                newOperandStack.add(new HashSet<>(original));
            }

            // set new state
            GotoState<T> newGotoState = new GotoState<>();
            newGotoState.setOperandStack(newOperandStack);
            newGotoState.setLocalVariables(newLocalVariables);
            gotoStates.put(label, newGotoState);
        }
    }

    /**
     * 模拟栈帧 的起点
     */
    @Override
    public void visitCode() {
        debugOption.debug = true;
        debugOption.clearSet();

        super.visitCode();
        localVariables.clear();
        operandStack.clear();

        // 如果为非静态方法,0号槽位存放this
        if ((this.access & Opcodes.ACC_STATIC) == 0) {
            localVariables.add(new HashSet<>());                 //这个位置是填放this的
        }
        //扫描的这个方法中有多少个入参，局部变量表中就填充多少个+1的 空map对象
        for (Type argType : Type.getArgumentTypes(desc)) {
            for (int i = 0; i < argType.getSize(); i++) {
                localVariables.add(new HashSet<>());
            }
        }
    }

    /**
     * 作用: 初始化操作数栈和局部变量表
     */
    @Override
    public void visitFrame(int type, int nLocal, Object[] local, int nStack, Object[] stack) {
        int stackSize = 0;
        // 获取操作数栈的数据,并根据数据类型决定长度(int是1字节,long/double是2字节)
        for (int i = 0; i < nStack; i++) {
            Object typ = stack[i];
            int objectSize = 1;
            if (typ.equals(Opcodes.LONG) || typ.equals(Opcodes.DOUBLE)) {
                objectSize = 2;
            }
            for (int j = operandStack.size(); j < stackSize + objectSize; j++) {
                operandStack.add(new HashSet<>());
            }
            stackSize += objectSize;
        }
        // 局部变量表同理
        int localSize = 0;
        for (int i = 0; i < nLocal; i++) {
            Object typ = local[i];
            int objectSize = 1;
            if (typ.equals(Opcodes.LONG) || typ.equals(Opcodes.DOUBLE)) {
                objectSize = 2;
            }
            for (int j = localVariables.size(); j < localSize + objectSize; j++) {
                localVariables.add(new HashSet<>());
            }
            localSize += objectSize;
        }

        // 删除多余部分
        for (int i = operandStack.size() - stackSize; i > 0; i--) {
            operandStack.remove(operandStack.size() - 1);
        }
        for (int i = localVariables.size() - localSize; i > 0; i--) {
            localVariables.remove(localVariables.size() - 1);
        }
        super.visitFrame(type, nLocal, local, nStack, stack);
        sanityCheck();
    }

    /**
     * 依据JVM文档对操作数栈进行相应的出栈和压栈
     */
    @Override
    public void visitInsn(int opcode) {
        Set<T> saved0, saved1, saved2, saved3;
        sanityCheck();
        switch (opcode) {
            case Opcodes.NOP:
                break;
            case Opcodes.ACONST_NULL:
            case Opcodes.ICONST_M1:
            case Opcodes.ICONST_0:
            case Opcodes.ICONST_1:
            case Opcodes.ICONST_2:
            case Opcodes.ICONST_3:
            case Opcodes.ICONST_4:
            case Opcodes.ICONST_5:
            case Opcodes.FCONST_0:
            case Opcodes.FCONST_1:
            case Opcodes.FCONST_2:
                operandStack.push();
                debugOption.setDebug(opcode);

                break;
            case Opcodes.LCONST_0:
            case Opcodes.LCONST_1:
            case Opcodes.DCONST_0:
            case Opcodes.DCONST_1:
                operandStack.push();
                operandStack.push();
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.IALOAD:
            case Opcodes.FALOAD:
            case Opcodes.AALOAD:
            case Opcodes.BALOAD:
            case Opcodes.CALOAD:
            case Opcodes.SALOAD:
                operandStack.pop();
                operandStack.pop();
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.LALOAD:
            case Opcodes.DALOAD:
                operandStack.pop();
                operandStack.pop();
                operandStack.push();
                operandStack.push();
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.IASTORE:
            case Opcodes.FASTORE:
            case Opcodes.AASTORE:
            case Opcodes.BASTORE:
            case Opcodes.CASTORE:
            case Opcodes.SASTORE:
                operandStack.pop();
                operandStack.pop();
                operandStack.pop();
                break;
            case Opcodes.LASTORE:
            case Opcodes.DASTORE:
                operandStack.pop();
                operandStack.pop();
                operandStack.pop();
                operandStack.pop();
                break;
            case Opcodes.POP:
                operandStack.pop();
                break;
            case Opcodes.POP2:
                operandStack.pop();
                operandStack.pop();
                break;
            case Opcodes.DUP:
                operandStack.push(operandStack.get(0));
                debugOption.setDebug(opcode);
                break;
            case Opcodes.DUP_X1:
                saved0 = operandStack.pop();
                saved1 = operandStack.pop();
                operandStack.push(saved0);
                operandStack.push(saved1);
                operandStack.push(saved0);
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.DUP_X2:
                saved0 = operandStack.pop();
                saved1 = operandStack.pop();
                saved2 = operandStack.pop();
                operandStack.push(saved0);
                operandStack.push(saved2);
                operandStack.push(saved1);
                operandStack.push(saved0);
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.DUP2:
                operandStack.push(operandStack.get(1));
                operandStack.push(operandStack.get(1));
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.DUP2_X1:
                saved0 = operandStack.pop();
                saved1 = operandStack.pop();
                saved2 = operandStack.pop();
                operandStack.push(saved1);
                operandStack.push(saved0);
                operandStack.push(saved2);
                operandStack.push(saved1);
                operandStack.push(saved0);
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.DUP2_X2:
                saved0 = operandStack.pop();
                saved1 = operandStack.pop();
                saved2 = operandStack.pop();
                saved3 = operandStack.pop();
                operandStack.push(saved1);
                operandStack.push(saved0);
                operandStack.push(saved3);
                operandStack.push(saved2);
                operandStack.push(saved1);
                operandStack.push(saved0);
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.SWAP:
                saved0 = operandStack.pop();
                saved1 = operandStack.pop();
                operandStack.push(saved0);
                operandStack.push(saved1);
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.IADD:
            case Opcodes.FADD:
            case Opcodes.ISUB:
            case Opcodes.FSUB:
            case Opcodes.IMUL:
            case Opcodes.FMUL:
            case Opcodes.IDIV:
            case Opcodes.FDIV:
            case Opcodes.IREM:
            case Opcodes.FREM:
                operandStack.pop();
                operandStack.pop();
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.LADD:
            case Opcodes.DADD:
            case Opcodes.LSUB:
            case Opcodes.DSUB:
            case Opcodes.LMUL:
            case Opcodes.DMUL:
            case Opcodes.LDIV:
            case Opcodes.DDIV:
            case Opcodes.LREM:
            case Opcodes.DREM:
                operandStack.pop();
                operandStack.pop();
                operandStack.pop();
                operandStack.pop();
                operandStack.push();
                operandStack.push();
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.INEG:
            case Opcodes.FNEG:
                operandStack.pop();
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.LNEG:
            case Opcodes.DNEG:
                operandStack.pop();
                operandStack.pop();
                operandStack.push();
                operandStack.push();
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.ISHL:
            case Opcodes.ISHR:
            case Opcodes.IUSHR:
                operandStack.pop();
                operandStack.pop();
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.LSHL:
            case Opcodes.LSHR:
            case Opcodes.LUSHR:
                operandStack.pop();
                operandStack.pop();
                operandStack.pop();
                operandStack.push();
                operandStack.push();
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.IAND:
            case Opcodes.IOR:
            case Opcodes.IXOR:
                operandStack.pop();
                operandStack.pop();
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.LAND:
            case Opcodes.LOR:
            case Opcodes.LXOR:
                operandStack.pop();
                operandStack.pop();
                operandStack.pop();
                operandStack.pop();
                operandStack.push();
                operandStack.push();
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.I2B:
            case Opcodes.I2C:
            case Opcodes.I2S:
            case Opcodes.I2F:
                operandStack.pop();
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.I2L:
            case Opcodes.I2D:
                operandStack.pop();
                operandStack.push();
                operandStack.push();
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.L2I:
            case Opcodes.L2F:
                operandStack.pop();
                operandStack.pop();
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.D2L:
            case Opcodes.L2D:
                operandStack.pop();
                operandStack.pop();
                operandStack.push();
                operandStack.push();
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.F2I:
                operandStack.pop();
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.F2L:
            case Opcodes.F2D:
                operandStack.pop();
                operandStack.push();
                operandStack.push();
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.D2I:
            case Opcodes.D2F:
                operandStack.pop();
                operandStack.pop();
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.LCMP:
                operandStack.pop();
                operandStack.pop();
                operandStack.pop();
                operandStack.pop();
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.FCMPL:
            case Opcodes.FCMPG:
                operandStack.pop();
                operandStack.pop();
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.DCMPL:
            case Opcodes.DCMPG:
                operandStack.pop();
                operandStack.pop();
                operandStack.pop();
                operandStack.pop();
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.IRETURN:
            case Opcodes.FRETURN:
            case Opcodes.ARETURN:
                operandStack.pop();
                break;
            case Opcodes.LRETURN:
            case Opcodes.DRETURN:
                operandStack.pop();
                operandStack.pop();
                break;
            case Opcodes.RETURN:
                break;
            case Opcodes.ARRAYLENGTH:
                operandStack.pop();
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.ATHROW:
                operandStack.pop();
                break;
            case Opcodes.MONITORENTER:
            case Opcodes.MONITOREXIT:
                operandStack.pop();
                break;
            default:
                throw new IllegalStateException("unsupported opcode: " + opcode);
        }
        super.visitInsn(opcode);
        sanityCheck();
    }

    /**
     * 依据JVM文档对操作数栈进行相应的出栈和压栈
     */
    @Override
    public void visitIntInsn(int opcode, int operand) {
        switch (opcode) {
            case Opcodes.BIPUSH:
            case Opcodes.SIPUSH:
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.NEWARRAY:
                operandStack.pop();
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            default:
                throw new IllegalStateException("unsupported opcode: " + opcode);
        }
        super.visitIntInsn(opcode, operand);
        sanityCheck();
    }

    /**
     * 赋值token给Var 格式: instruction-token-var-isExit
     */
    public void setTokenWithVar(int var) {
        Set instruction = new HashSet<>();
        // 如果 isExit 为 0的话,说明token没有赋值,需要赋值,否则不赋值token
        Set sets = localVariables.get(var);
        for (Object set : sets) {
            if (set instanceof String && ((String) set).indexOf("instruction") > -1 && new Integer(stringUtils.splitBySymbol((String) set, "-")[3]) == 0) {
                instruction.add("instruction" + "-" + CoreMethodAdapter.token + "-" + var + "-" + 1);
                localVariables.get(var).addAll(instruction);
            } else {

            }
        }
    }

    /**
     * 通过模拟栈帧,对被使用的变量分别下标记
     * var: 在LV中的下标
     */
    @Override
    public void visitVarInsn(int opcode, int var) {
        for (int i = localVariables.size(); i <= var; i++) {
            localVariables.add(new HashSet<>());
        }
        Set<T> saved0;
        switch (opcode) {
            case Opcodes.ILOAD:
            case Opcodes.FLOAD:
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.LLOAD:
            case Opcodes.DLOAD:
                operandStack.push();
                operandStack.push();
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.ALOAD:
                operandStack.push(localVariables.get(var));
                debugOption.setDebug(opcode);
                break;
            case Opcodes.ISTORE:
            case Opcodes.FSTORE:
                operandStack.pop();
                localVariables.set(var, new HashSet<>());
                break;
            case Opcodes.DSTORE:
            case Opcodes.LSTORE:
                operandStack.pop();
                operandStack.pop();
                localVariables.set(var, new HashSet<>());
                break;
            case Opcodes.ASTORE:
                saved0 = operandStack.pop();
                localVariables.set(var, saved0);

                //像一些方法如，list.add(taint) taint是可以污染list的，但是当list.add(taint)调用完之后,list已经不在栈内了，无法给栈上的数据污染，所以这种情况
                //直接给操作数表上的对应做上污染标记:instruction1表示，这个对象或值来自操作数表一号位置
                // setTokenWithVar(var);
                Set instruction = new HashSet<>();
                instruction.add("instruction" + var);
                localVariables.get(var).addAll(instruction);

                break;
            case Opcodes.RET:
                break;
            default:
                throw new IllegalStateException("unsupported opcode: " + opcode);
        }
        super.visitVarInsn(opcode, var);
        sanityCheck();
    }

    /**
     * 依据JVM文档对操作数栈进行相应的出栈和压栈
     */
    @Override
    public void visitTypeInsn(int opcode, String type) {
        switch (opcode) {
            case Opcodes.NEW:
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.ANEWARRAY:
                operandStack.pop();
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.CHECKCAST:
                break;
            case Opcodes.INSTANCEOF:
                operandStack.pop();
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            default:
                throw new IllegalStateException("unsupported opcode: " + opcode);
        }
        super.visitTypeInsn(opcode, type);
        sanityCheck();
    }

    /**
     * 对 Field 进行相应的出栈压栈
     */
    @Override
    public void visitFieldInsn(int opcode, String owner, String name, String desc) {
        int typeSize = Type.getType(desc).getSize();
        switch (opcode) {
            case Opcodes.GETSTATIC:
                for (int i = 0; i < typeSize; i++) {
                    operandStack.push();
                    debugOption.setDebug(opcode);
                }
                break;
            case Opcodes.PUTSTATIC:
                for (int i = 0; i < typeSize; i++) {
                    operandStack.pop();
                }
                break;
            case Opcodes.GETFIELD:
                operandStack.pop();
                for (int i = 0; i < typeSize; i++) {
                    operandStack.push();
                    debugOption.setDebug(opcode);
                }
                break;
            case Opcodes.PUTFIELD:
                for (int i = 0; i < typeSize; i++) {
                    operandStack.pop();
                }
                operandStack.pop();
                break;
            default:
                throw new IllegalStateException("unsupported opcode: " + opcode);
        }
        super.visitFieldInsn(opcode, owner, name, desc);
        sanityCheck();
    }

    /**
     * 获取method的参数类型
     */
    public Type[] getMethodType(int opcode, String owner, String name, String desc, boolean itf) {
        Type[] argTypes = Type.getArgumentTypes(desc);
        if (opcode != Opcodes.INVOKESTATIC) {
            Type[] extendedArgTypes = new Type[argTypes.length + 1];
            System.arraycopy(argTypes, 0, extendedArgTypes, 1, argTypes.length);
            extendedArgTypes[0] = Type.getObjectType(owner);
            argTypes = extendedArgTypes;
        }
        return argTypes;
    }

    /**
     * 处理匿名内部类
     */
    public void handleAnonymousClass(CoreMethodAdapter coreMethodAdapter, String owner, Type[] argTypes, List<Set<T>> argTaint) {
        isTest = false;
        // 统计函数的arg的总大小
        int totalSizeOfArg = 0;
        for (int i = 0; i < argTypes.length; i++) {
            Type argType = argTypes[i];
            if (argType.getSize() > 0) {
                totalSizeOfArg = argType.getSize() + totalSizeOfArg;
            }
        }

        // 1.处理非正常情况
        int counter = 0;
        if ((coreMethodAdapter.operandStack.size() <= totalSizeOfArg)) {
            try {
                List<Object> list2 = new ArrayList<>();
                Class cls = Class.forName("org.objectweb.asm.commons.AnalyzerAdapter");
                Field stack = cls.getDeclaredField("stack");
                stack.setAccessible(true);

                // 第一种情况: 匿名内部类
                if (coreMethodAdapter.operandStack.size() < totalSizeOfArg) {
                    // 将set中的所有项全部封装为set(例如 set0{1,2,3} => set1,set2,set3 )
                    int stackSize = operandStack.size();
                    for (int i = 0; i <= stackSize - 1; i++) {
                        // 如果存在值,才进行相应操作
                        Set test = coreMethodAdapter.operandStack.get(i);
                        List<T> list = new ArrayList<T>(test);
                        for (int top = test.size() - 1; top >= 0; top--) {
                            // 获取 此set中的某一项(从高到低),并赋值给 value
                            T value = list.get(top);
                            if (!value.equals("")) {
                                // value再重新封装为一个新set,并传给 argTaint
                                Set subSetItem = new HashSet();
                                subSetItem.add(value);
                                argTaint.set(argTypes.length - 1 - counter, subSetItem);
                            }
                            counter++;
                        }
                    }

                    for (int i = 0; i <= coreMethodAdapter.operandStack.size() - 1; i++) {
                        coreMethodAdapter.operandStack.pop();
                    }

                    list2.add(owner);
                    List tmpList = (List) stack.get(coreMethodAdapter.mv);
                    String tmpString = (String) tmpList.get(0);
                    list2.add(tmpString);
                    stack.set(coreMethodAdapter.mv, list2);
                } else {
                    //第二种情况: operandStack.size() == totalSizeOfArg,根据每个参数的大小进行相应的弹栈
                    for (int i = 0; i < argTypes.length; i++) {
                        Type argType = argTypes[i];
                        if (argType.getSize() > 0) {
                            // 弹栈的目的是模拟 执行方法
                            for (int j = 0; j < argType.getSize() - 1; j++) {
                                operandStack.pop();
                                //totalSizeOfArg = totalSizeOfArg - argType.getSize();
                            }
                            // 记录方法参数
                            argTaint.set(argTypes.length - 1 - i, operandStack.pop());
                        }
                    }
                    isTest = true;
                }
            } catch (ClassNotFoundException e) {
                throw new RuntimeException(e);
            } catch (NoSuchFieldException e) {
                throw new RuntimeException(e);
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        } else {
        // 2.处理正常情况
            for (int i = 0; i < argTypes.length; i++) {
                Type argType = argTypes[i];
                if (argType.getSize() > 0) {

                    // 弹栈的目的是模拟 执行方法
                    for (int j = 0; j < argType.getSize() - 1; j++) {
                        operandStack.pop();
                    }
                    // 记录方法参数
                    argTaint.set(argTypes.length - 1 - i, operandStack.pop());
                }
            }
        }

    }

    /**
     * 对方法调用中的参数进行污点分析
     */
    @Override
    public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf)
    {
        if (owner.equals("java/lang/String") &&  name.equals("<init>") && desc.equals("(Ljava/lang/String;)V")) {
//            System.out.println("sb");
//            System.out.println(analyzerAdapter.stack.size());
            debugOption.setOwner(owner,name,desc);
            debugOption.printDebug();
        }

        // 获取method的参数类型
        Type[] argTypes = getMethodType(opcode, owner, name, desc, itf);
        final Type returnType = Type.getReturnType(desc);
        final int retSize = returnType.getSize();
        Set<T> resultTaint;
        switch (opcode) {
            case Opcodes.INVOKESTATIC:
            case Opcodes.INVOKEVIRTUAL:
            case Opcodes.INVOKESPECIAL:
            case Opcodes.INVOKEINTERFACE:
                final List<Set<T>> argTaint = new ArrayList<>(argTypes.length);
                for (int i = 0; i < argTypes.length; i++) {
                    argTaint.add(null);
                }

                Type argType;
                // 处理匿名内部类
                handleAnonymousClass(this, owner, argTypes, argTaint);

                // []
                if (name.equals("<init>")) {
                    resultTaint = argTaint.get(0);
                } else {
                    resultTaint = new HashSet<>();
                }

                // todo 3 在名单内的方法的调用，已预置哪个参数可以污染返回值 (?)
                // 白名单匹配 污点源
                for (Object[] passthrough : PASSTHROUGH_DATAFLOW) {
                    // 如果符合我们的白名单的某一项,就将 这一项中能影响返回值的方法参数传入 resultTaint
                    if (passthrough[0].equals(owner) && passthrough[1].equals(name) && (passthrough[2].equals(desc) || passthrough[2].equals("*"))) {
                        for (int i = 3; i < passthrough.length; i++) {
                            // test 处理特殊情况
//                            Integer integer1 = (Integer) passthrough[i];
//                            Integer integer2 = -1;
//                            if(i == 3 && integer1 == integer2){
//                                Set test1 = new HashSet();
//                                test1.add((Integer) 1);
//                                resultTaint.addAll(test1);
//                            }else {
//                                resultTaint.addAll(argTaint.get((Integer) passthrough[i]));
//                            }
                            resultTaint.addAll(argTaint.get((Integer) passthrough[i]));
                        }
                        break;
                    }
                }
                // 处理list.add这个特殊情况
                if ((owner.equals("java/util/List") && name.equals("add") && desc.equals("(Ljava/lang/Object;)Z"))) {
                    // TODO 解决 "继承list" 的绕过
                    Set<T> set = argTaint.get(0);
                    // 将污点:"list.add(taint)" 添加到 resultTaint,通过获取list数组中taint所在下标，进而获取到taint,最后再添加到resultTaint
                    for (Object taint : set) {
                        if (taint instanceof String && ((String) taint).indexOf("instruction") > -1 && resultTaint.size() > 0) {
                            String localVariablesNum = ((String) taint).substring(11);
                            localVariables.get(new Integer(localVariablesNum)).addAll(resultTaint);
                            break;
                        }
                    }
                }

                if (retSize > 0) {
                    // 为什么返回值大于0就要将resultTaint压入操作数栈呢? 因为:为了让上层函数去污点分析
                    // 否则如果是没有返回值的话,那根本不用把 resultTaint 向上传递,说明此函数根本就是摆设
                    operandStack.push(resultTaint);
                    debugOption.setDebug(opcode);
                    for (int i = 1; i < retSize; i++) {
                        operandStack.push();
                        debugOption.setDebug(opcode);
                    }
                }
                break;
            default:
                throw new IllegalStateException("unsupported opcode: " + opcode);
        }
        super.visitMethodInsn(opcode, owner, name, desc, itf);

        //处理当return new String(evilCode)这种情况，构造方法返回值为retSize为0，但其实他可以污染 上层函数(所有方法参数出栈后的栈顶)
        if (retSize == 0 && operandStack.size() > 0 && resultTaint != null && resultTaint.size() > 0) {
            operandStack.get(0).addAll(resultTaint);
        }
        sanityCheck();
        debugOption.clearSet();
    }

    /**
     * 对方法执行进行污点分析
     */
    @Override
    public void visitInvokeDynamicInsn(String name, String desc, Handle bsm, Object... bsmArgs) {
        int argsSize = 0;
        for (Type type : Type.getArgumentTypes(desc)) {
            argsSize += type.getSize();
        }
        int retSize = Type.getReturnType(desc).getSize();
        // 调用方法时,所用参数全部出栈,如果有返回值,则将返回值压入栈中
        for (int i = 0; i < argsSize; i++) {
            operandStack.pop();
        }
        for (int i = 0; i < retSize; i++) {
            operandStack.push();

        }
        super.visitInvokeDynamicInsn(name, desc, bsm, bsmArgs);
        sanityCheck();
    }

    /**
     * 对代码中的jump进行相应的出栈压栈,和label的跳转
     */
    @Override
    public void visitJumpInsn(int opcode, Label label) {
        switch (opcode) {
            case Opcodes.IFEQ:
            case Opcodes.IFNE:
            case Opcodes.IFLT:
            case Opcodes.IFGE:
            case Opcodes.IFGT:
            case Opcodes.IFLE:
            case Opcodes.IFNULL:
            case Opcodes.IFNONNULL:
                operandStack.pop();
                break;
            case Opcodes.IF_ICMPEQ:
            case Opcodes.IF_ICMPNE:
            case Opcodes.IF_ICMPLT:
            case Opcodes.IF_ICMPGE:
            case Opcodes.IF_ICMPGT:
            case Opcodes.IF_ICMPLE:
            case Opcodes.IF_ACMPEQ:
            case Opcodes.IF_ACMPNE:
                operandStack.pop();
                operandStack.pop();
                break;
            case Opcodes.GOTO:
                break;
            case Opcodes.JSR:
                operandStack.push();
                debugOption.setDebug(opcode);
                super.visitJumpInsn(opcode, label);
                return;
            default:
                throw new IllegalStateException("unsupported opcode: " + opcode);
        }
        mergeGotoState(label);
        super.visitJumpInsn(opcode, label);
        sanityCheck();
    }

    /**
     * 对label 进行相应处理
     */
    @Override
    public void visitLabel(Label label) {
        if (gotoStates.containsKey(label)) {
            GotoState<T> state = gotoStates.get(label);
            // old -> label
            LocalVariables<T> oldLocalVariables = state.getLocalVariables();
            OperandStack<T> oldOperandStack = state.getOperandStack();
            // new -> null
            LocalVariables<T> newLocalVariables = new LocalVariables<>();
            OperandStack<T> newOperandStack = new OperandStack<>();
            // init new
            for (Set<T> original : oldLocalVariables.getList()) {
                newLocalVariables.add(new HashSet<>(original));
            }
            for (Set<T> original : oldOperandStack.getList()) {
                newOperandStack.add(new HashSet<>(original));
            }
            this.operandStack = newOperandStack;
            this.localVariables = newLocalVariables;
        }
        if (exceptionHandlerLabels.contains(label)) {
            operandStack.push(new HashSet<>());

        }
        super.visitLabel(label);
        sanityCheck();
    }

    // TODO 存在问题?
    /**
     * 对载入字符串进行相应处理
     */
    @Override
    public void visitLdcInsn(Object cst) {
        if (cst instanceof Long || cst instanceof Double) {
            operandStack.push();
            operandStack.push();
        } else {
            operandStack.push();
        }
        super.visitLdcInsn(cst);
        sanityCheck();
    }

    @Override
    public void visitIincInsn(int var, int increment) {
        super.visitIincInsn(var, increment);
        sanityCheck();
    }

    /**
     * 对switch进行相应处理
     */
    @Override
    public void visitTableSwitchInsn(int min, int max, Label dflt, Label... labels) {
        operandStack.pop();
        mergeGotoState(dflt);
        for (Label label : labels) {
            mergeGotoState(label);
        }
        super.visitTableSwitchInsn(min, max, dflt, labels);
        sanityCheck();
    }

    /**
     * 对switch进行相应处理
     */
    @Override
    public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) {
        operandStack.pop();
        mergeGotoState(dflt);
        for (Label label : labels) {
            mergeGotoState(label);
        }
        super.visitLookupSwitchInsn(dflt, keys, labels);
        sanityCheck();
    }

    @Override
    public void visitMultiANewArrayInsn(String desc, int dims) {
        for (int i = 0; i < dims; i++) {
            operandStack.pop();
        }
        operandStack.push();
        super.visitMultiANewArrayInsn(desc, dims);
        sanityCheck();
    }

    @Override
    public AnnotationVisitor visitInsnAnnotation(int typeRef, TypePath typePath, String desc, boolean visible) {
        return super.visitInsnAnnotation(typeRef, typePath, desc, visible);
    }

    /**
     * 对try-catch进行相应处理
     */
    @Override
    public void visitTryCatchBlock(Label start, Label end, Label handler, String type) {
        exceptionHandlerLabels.add(handler);
        super.visitTryCatchBlock(start, end, handler, type);
    }

    /**
     * 对try-catch进行相应处理
     */
    @Override
    public AnnotationVisitor visitTryCatchAnnotation(int typeRef, TypePath typePath, String desc, boolean visible) {
        return super.visitTryCatchAnnotation(typeRef, typePath, desc, visible);
    }

    @Override
    public void visitMaxs(int maxStack, int maxLocals) {
        super.visitMaxs(maxStack, maxLocals);
    }

    /**
     * MethodVisitor 执行结束
     */
    @Override
    public void visitEnd() {
        super.visitEnd();
    }
}
