package org.sec.ImitateJVM;

import org.apache.log4j.Logger;
import org.objectweb.asm.*;
import org.objectweb.asm.commons.AnalyzerAdapter;
import org.sec.Scan.getAllString;
import org.sec.utils.FileUtils;
import org.sec.utils.stringUtils;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.sec.Scan.stainSource.PASSTHROUGH_DATAFLOW;

/**
 * 模拟栈帧的核心方法
 */
@SuppressWarnings("all")
public class CoreMethodAdapter<T> extends MethodVisitor {
    // 操作数栈的大小和totalSizeOfArg的大小是否相等
    public static boolean isSizeEqual = false;
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
    public static String[] finalPassthrough;
    public static List<String> lines = new ArrayList<>();

    // Stain source
    static {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("\t");
        for (Object[] passthrough : PASSTHROUGH_DATAFLOW) {
            for (int i = 3; i < passthrough.length; i++) {
                stringBuilder.append((Integer) passthrough[i]);
                stringBuilder.append(',');
            }
            lines.add(passthrough[0] + "\t" + passthrough[1] + "\t" + passthrough[2] + stringBuilder);
            stringBuilder.delete(1, stringBuilder.length());
        }

        // 如果没有stainSource.txt则创建,并写入内置污点源
        File stainSource = new File("." + File.separator + "stainSource.txt");
        if (!stainSource.exists()) {
            try {
                stainSource.createNewFile();
                FileUtils.writeLines("." + File.separator + "stainSource.txt", lines);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    // 是否开启debug选项
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
     * 控制 operandStack.pop,并进行安全检查
     */
    public Set controlPopCount(int popCount) {
        Set save0 = null;
        for (int i = 0; i < popCount; i++) {
            while (operandStack.size() == 0) {
                Field stack = ChangeAsmVar.getAsmStack();
                // 修改模拟的 stack
                operandStack.push();
                // 修改asm的stack
                try {
                    List tmpList = (List) stack.get(this.mv);
                    tmpList.add(new HashSet<>());
                    stack.set(this.mv, tmpList);
                } catch (IllegalAccessException e) {
                    throw new RuntimeException(e);
                }
            }
            save0 = operandStack.pop();
        }
        return save0;
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
        // 开发时需要调试的时候开启: debugOption.systemDebug = true;
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
                controlPopCount(2);
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.LALOAD:
            case Opcodes.DALOAD:
                controlPopCount(2);
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
                controlPopCount(3);
                break;
            case Opcodes.LASTORE:
            case Opcodes.DASTORE:
                controlPopCount(4);
                break;
            case Opcodes.POP:
                controlPopCount(1);
                break;
            case Opcodes.POP2:
                controlPopCount(2);
                break;
            case Opcodes.DUP:
                operandStack.push(operandStack.get(0));
                debugOption.setDebug(opcode);
                break;
            case Opcodes.DUP_X1:
                saved0 = controlPopCount(1);
                saved1 = controlPopCount(1);
                operandStack.push(saved0);
                operandStack.push(saved1);
                operandStack.push(saved0);
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.DUP_X2:
                saved0 = controlPopCount(1);
                saved1 = controlPopCount(1);
                saved2 = controlPopCount(1);
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
                saved0 = controlPopCount(1);
                saved1 = controlPopCount(1);
                saved2 = controlPopCount(1);
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
                saved0 = controlPopCount(1);
                saved1 = controlPopCount(1);
                saved2 = controlPopCount(1);
                saved3 = controlPopCount(1);
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
                saved0 = controlPopCount(1);
                saved1 = controlPopCount(1);
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
                controlPopCount(2);
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
                controlPopCount(4);
                operandStack.push();
                operandStack.push();
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.INEG:
            case Opcodes.FNEG:
                controlPopCount(1);
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.LNEG:
            case Opcodes.DNEG:
                controlPopCount(2);
                operandStack.push();
                operandStack.push();
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.ISHL:
            case Opcodes.ISHR:
            case Opcodes.IUSHR:
                controlPopCount(2);
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.LSHL:
            case Opcodes.LSHR:
            case Opcodes.LUSHR:
                controlPopCount(3);
                operandStack.push();
                operandStack.push();
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.IAND:
            case Opcodes.IOR:
            case Opcodes.IXOR:
                controlPopCount(2);
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.LAND:
            case Opcodes.LOR:
            case Opcodes.LXOR:
                controlPopCount(4);
                operandStack.push();
                operandStack.push();
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.I2B:
            case Opcodes.I2C:
            case Opcodes.I2S:
            case Opcodes.I2F:
                controlPopCount(1);
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.I2L:
            case Opcodes.I2D:
                controlPopCount(1);
                operandStack.push();
                operandStack.push();
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.L2I:
            case Opcodes.L2F:
                controlPopCount(2);
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.D2L:
            case Opcodes.L2D:
                controlPopCount(2);
                operandStack.push();
                operandStack.push();
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.F2I:
                controlPopCount(1);
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.F2L:
            case Opcodes.F2D:
                controlPopCount(1);
                operandStack.push();
                operandStack.push();
                debugOption.setDebug(opcode);
                debugOption.setDebug(opcode);
                break;
            case Opcodes.D2I:
            case Opcodes.D2F:
                controlPopCount(2);
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.LCMP:
                controlPopCount(4);
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.FCMPL:
            case Opcodes.FCMPG:
                controlPopCount(2);
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.DCMPL:
            case Opcodes.DCMPG:
                controlPopCount(4);
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.IRETURN:
            case Opcodes.FRETURN:
            case Opcodes.ARETURN:
                controlPopCount(1);
                break;
            case Opcodes.LRETURN:
            case Opcodes.DRETURN:
                controlPopCount(2);
                break;
            case Opcodes.RETURN:
                break;
            case Opcodes.ARRAYLENGTH:
                controlPopCount(1);
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.ATHROW:
                controlPopCount(1);
                break;
            case Opcodes.MONITORENTER:
            case Opcodes.MONITOREXIT:
                controlPopCount(1);
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
     * 通过模拟栈帧,对被使用的变量分别下标记
     * var: 在LV中的下标
     */
    @Override
    public void visitVarInsn(int opcode, int var) {
        for (int i = localVariables.size(); i <= var; i++) {
            localVariables.add(new HashSet<>());
        }
        Set<T> saved0 = null;
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
                // 非正常情况
                if (operandStack.size() == 0) {
                    List<Object> list2 = new ArrayList<>();
                    Class cls = null;
                    Field stack = null;
                    try {
                        stack = ChangeAsmVar.getAsmStack();
                        list2.add(1);
                        List tmpList = (List) stack.get(this.mv);
                        stack.set(this.mv, list2);
                        saved0 = new HashSet<>();
                        saved0.add((T) (Integer) 1);

                    } catch (IllegalAccessException e) {
                        throw new RuntimeException(e);
                    }
                } else {
                    // 正常情况
                    saved0 = operandStack.pop();
                    localVariables.set(var, saved0);
                }
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
                controlPopCount(1);
                operandStack.push();
                debugOption.setDebug(opcode);
                break;
            case Opcodes.CHECKCAST:
                break;
            case Opcodes.INSTANCEOF:
                controlPopCount(1);
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
                if (operandStack.size() == 0) {
                    Field stack = null;
                    try {
                        stack = ChangeAsmVar.getAsmStack();
                        List tmpList = (List) stack.get(this.mv);
                        int tmpSize = tmpList.size();
                        for (int i = 0; i <= tmpSize - 1; i++) {
                            tmpList.add(new HashSet<>());
                        }
                        stack.set(this.mv, tmpList);
                    } catch (IllegalAccessException e) {
                        throw new RuntimeException(e);
                    }
                } else {
                    operandStack.pop();
                }
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
     * 模拟方法执行
     */
    public void simulationMethod(CoreMethodAdapter coreMethodAdapter, String owner, Type[] argTypes, List<Set<T>> argTaint) {
        isSizeEqual = false;
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
                            }
                            // 记录方法参数
                            argTaint.set(argTypes.length - 1 - i, operandStack.pop());
                        }
                    }
                    isSizeEqual = true;
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
    public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
        debugOption.setFilter("java/io/ByteArrayInputStream", "<init>", "([BII)V");
        debugOption.filter(owner, name, desc);

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
                // 模拟方法执行
                simulationMethod(this, owner, argTypes, argTaint);

                if (name.equals("<init>")) {
                    resultTaint = argTaint.get(0);
                } else {
                    resultTaint = new HashSet<>();
                }

                // 黑名单匹配 污点源
                lines = FileUtils.readLines(".\\stainSource.txt", String.valueOf(StandardCharsets.UTF_8));
                for (String line : lines) {
                    // 按\t进行切割
                    String[] finalPassthrough = stringUtils.splitBySymbol(line, "\t");
                    // 如果符合我们的黑名单的某一项,就将 这一项中能影响返回值的方法参数传入 resultTaint
                    if (finalPassthrough[0].equals(owner) && finalPassthrough[1].equals(name) && (finalPassthrough[2].equals(desc) || finalPassthrough[2].equals("*"))) {
                        String[] middle = stringUtils.splitBySymbol(finalPassthrough[3], ",");
                        for (int i = 0; i < middle.length; i++) {
                            resultTaint.addAll(argTaint.get((Integer) Integer.parseInt(middle[i])));
                        }
                        //System.out.println(finalPassthrough[0]+"  "+ finalPassthrough[1] );

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
        } else if (owner.equals("java/lang/String") && name.equals("<init>") && desc.equals("([B)V") && retSize == 0 && operandStack.size() > 0 && resultTaint != null) {
            // 解决 new String直接扔入函数中，会导致无法检测的问题.解决方案:自己造一个污点,用于传递
            resultTaint = operandStack.get(operandStack.size() - 1);
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
                controlPopCount(1);
                break;
            case Opcodes.IF_ICMPEQ:
            case Opcodes.IF_ICMPNE:
            case Opcodes.IF_ICMPLT:
            case Opcodes.IF_ICMPGE:
            case Opcodes.IF_ICMPGT:
            case Opcodes.IF_ICMPLE:
            case Opcodes.IF_ACMPEQ:
            case Opcodes.IF_ACMPNE:
                controlPopCount(2);
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
            // 可能是String类型,遍历输出String类型,密码可能就存在里面
            String tmpStr = cst.toString();
            getAllString.stringsList.add(tmpStr);
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
