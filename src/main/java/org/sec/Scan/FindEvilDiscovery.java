package org.sec.Scan;

import org.apache.log4j.Logger;
import org.objectweb.asm.*;
import org.objectweb.asm.commons.JSRInlinerAdapter;
import org.sec.ImitateJVM.Constant;
import org.sec.Data.MethodReference;
import org.sec.ImitateJVM.ChangeAsmVar;
import org.sec.ImitateJVM.CoreMethodAdapter;
import org.sec.ImitateJVM.currentClassQueue;
import org.sec.Scan.JVMMethodScan.InvokeInterface;
import org.sec.Scan.JVMMethodScan.InvokeSpecial;
import org.sec.Scan.JVMMethodScan.InvokeStatic;
import org.sec.Scan.JVMMethodScan.InvokeVirtual;

import java.lang.reflect.Field;
import java.util.*;

/**
 * 寻找有没有 request 请求能控制的值可以流入恶意方法的，如 Runtime.exec ， ProcessBuilder
 */
public class FindEvilDiscovery {
    private static final Logger logger = Logger.getLogger(FindEvilDiscovery.class);
    public static ArrayList<String> innerClassList = new ArrayList<>();

    public void findEvilDataflow(boolean delete) {
        currentClassQueue.initClassQueue("", "_jspService"); // test
        final Map<MethodReference.Handle, Map<String, Set<Integer>>> EvilDataflow = new HashMap<>();
        for (MethodReference.Handle methodToVisit : Constant.sortedMethodCalls) {
            String className = methodToVisit.getOwner().substring(methodToVisit.getOwner().lastIndexOf("/") + 1);
            byte[] classByte = Constant.classNameToByte.get(className);
            ClassReader cr = new ClassReader(classByte);
            FindEvilDataflowClassVisitor findEvilDataflowClassVisitor = new FindEvilDataflowClassVisitor(EvilDataflow, Opcodes.ASM5, methodToVisit, Constant.classNameToClassFileName.get(className), delete);
            cr.accept(findEvilDataflowClassVisitor, ClassReader.EXPAND_FRAMES);
        }
    }

    private class FindEvilDataflowClassVisitor extends ClassVisitor {
        private FindEvilDataflowMethodVisitor findEvilDataflowMethodVisitor;
        private final Map<MethodReference.Handle, Map<String, Set<Integer>>> EvilDataflow;
        private final MethodReference.Handle methodToVisit;
        private String name;
        private final String classFileName;
        private final Set<Integer> printEvilMessage = new HashSet<>();

        private boolean isDelete = false;

        public FindEvilDataflowClassVisitor(Map<MethodReference.Handle, Map<String, Set<Integer>>> EvilDataflow, int api, MethodReference.Handle methodToVisit, String classFileName, boolean delete) {
            super(api);
            this.EvilDataflow = EvilDataflow;
            this.methodToVisit = methodToVisit;
            this.classFileName = classFileName;
            this.isDelete = delete;
        }

        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            super.visit(version, access, name, signature, superName, interfaces);
            this.name = name;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            //对method进行观察
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            if (name.equals(this.methodToVisit.getName())) {
                Constant.isPrintDecompileInfo = name.equals("_jspService") && descriptor.equals("(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V");

                findEvilDataflowMethodVisitor = new FindEvilDataflowMethodVisitor(EvilDataflow, Opcodes.ASM5, access, descriptor, mv, this.name, name, signature, exceptions, classFileName, printEvilMessage, isDelete);
                EvilDataflow.put(new MethodReference.Handle(this.name, name, descriptor), getReturnTaint());
                return new JSRInlinerAdapter(findEvilDataflowMethodVisitor, access, name, descriptor, signature, exceptions);
            }
            return super.visitMethod(access, name, descriptor, signature, exceptions);
        }

        /**
         * 检测内部类,然后进行相应的操作
         **/
        // TODO 解决内部类的问题
        // 我的思路: 设置一个暂存类1和暂存类2,用于表示当前所处的类环境.如果执行的过程遇到了内部类，就更新暂存类1和2，将暂存类2顺延到暂存类1,内部类放置到暂存类2
        @Override
        public void visitInnerClass(String name, String outerName, String innerName, int access) {
            //System.out.println("name is: "+name+" outName is: " + outerName + " Detected inner class:" + innerName);
            // TODO 解决 原生类会执行 updateClassQueue
            if (!innerClassList.contains(name) && name.contains("org/apache/jsp/")) {
                currentClassQueue.updateClassQueue(name);
                innerClassList.add(name);
            }

            super.visitInnerClass(name, outerName, innerName, access);
        }

        public Map<String, Set<Integer>> getReturnTaint() {
            if (findEvilDataflowMethodVisitor == null) {
                throw new IllegalStateException("Never constructed the passthroughDataflowmethodVisitor!");
            }
            return findEvilDataflowMethodVisitor.toEvilTaint;
        }
    }

    public static class FindEvilDataflowMethodVisitor extends CoreMethodAdapter {
        private final Map<String, Set<Integer>> toEvilTaint;//被污染的返回数据,key的值为恶意类的类型，比如:Runtime/ProcessBuilder/Behinder
        public Map<MethodReference.Handle, Map<String, Set<Integer>>> EvilDataflow;
        private final int access;
        private final String desc;
        private final String owner;
        public final String name;
        private final boolean isStatic;
        public String classFileName;
        public Set<Integer> printEvilMessage;

        private final boolean isDelete;

        public FindEvilDataflowMethodVisitor(Map<MethodReference.Handle, Map<String, Set<Integer>>> EvilDataflow, int api, int access, String desc, MethodVisitor mv, String owner, String name, String signature, String[] exceptions, String classFileName, Set<Integer> printEvilMessage, boolean isDelete) {
            super(api, mv, owner, access, name, desc, signature, exceptions);
            this.EvilDataflow = EvilDataflow;
            this.toEvilTaint = new HashMap<>();
            this.access = access;
            this.desc = desc;
            this.owner = owner;
            this.name = name;
            this.isStatic = (access & Opcodes.ACC_STATIC) != 0;
            this.classFileName = classFileName;
            this.printEvilMessage = printEvilMessage;
            this.isDelete = isDelete;
        }

        @Override
        public void visitCode() {
            super.visitCode();

            int localIndex = 0;
            int argIndex = 0;
            if ((this.access & Opcodes.ACC_STATIC) == 0) {
                //非静态方法，第一个局部变量应该为对象实例this
                //添加到本地变量表集合
                setLocalTaint(localIndex, argIndex);
                localIndex += 1;
                argIndex += 1;
            }
            for (Type argType : Type.getArgumentTypes(desc)) {
                //判断参数类型，得出变量占用空间大小，然后存储
                setLocalTaint(localIndex, argIndex);
                localIndex += argType.getSize();
                argIndex += 1;
            }
        }

        public void visitMethodInsnForSuper(int opcode, String owner, String name, String desc, boolean itf){
            super.visitMethodInsn(opcode, owner, name, desc, itf);
        }

        /**
         * 污点分析,和输出污点分析结果
         */
        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
            // 1-1 通过 desc 获取 类名,即owner
            Type[] argTypes = Type.getArgumentTypes(desc);

            // 1-2 获取返回值类型大小
            int retSize = Type.getReturnType(desc).getSize();

            Set<Integer> resultTaint;
            //非静态方法需要把实例类型放在第一个元素
            if (opcode != Opcodes.INVOKESTATIC) {
                Type[] extendedArgTypes = new Type[argTypes.length + 1];
                System.arraycopy(argTypes, 0, extendedArgTypes, 1, argTypes.length);
                extendedArgTypes[0] = Type.getObjectType(owner);
                argTypes = extendedArgTypes;
            }
            final List<Set<Integer>> argTaint = new ArrayList<>(argTypes.length);
            // 这个switch用于模拟栈帧,模拟出污点流方向
            switch (opcode) {
                case Opcodes.INVOKESTATIC:
                case Opcodes.INVOKEINTERFACE:
                case Opcodes.INVOKEVIRTUAL:
                case Opcodes.INVOKESPECIAL:
                    // 初始化
                    for (int i = 0; i < argTypes.length; i++) {
                        argTaint.add(null);
                    }

                    // 将operandStack中的数据全部迁移到argTaint
                    int stackIndex = 0;
                    for (int i = 0; i < argTypes.length; i++) {
                        Type argType = argTypes[i];
                        if (argType.getSize() > 0) {
                            //栈顶对应被调用方法最右边的参数
                            int getIndex = stackIndex + argType.getSize() - 1;
                            Set argSet;
                            // 处理非正常情况
                            if (getIndex > operandStack.size() - 1) {
                                Field stack;
                                stack = ChangeAsmVar.getAsmStack();
                                int count = 0;
                                int tmpOperandStackSize = operandStack.size() + 1;
                                for (int num = 0; num < (tmpOperandStackSize - getIndex); num++) {
                                    operandStack.push();
                                    count++;
                                }
                                // 修改asm的stack
                                try {
                                    List tmpList = (List) stack.get(this.mv);
                                    for (int num1 = 0; num1 <= count - 1; num1++) {
                                        tmpList.add(new HashSet<>());
                                    }
                                    stack.set(this.mv, tmpList);
                                    argSet = operandStack.get(getIndex);
                                } catch (IllegalAccessException e) {
                                    throw new RuntimeException(e);
                                }
                            } else {
                                argSet = operandStack.get(getIndex);
                            }

                            argTaint.set(argTypes.length - 1 - i, argSet);
                        }
                        stackIndex += argType.getSize();
                    }

                    // 构造方法的调用，意味参数0可以污染返回值
                    if (name.equals("<init>")) {
                        // 将结果污点传递到原始污点集,初始化的对象直接被参数污染
                        resultTaint = argTaint.get(0);
                    } else {
                        resultTaint = new HashSet<>();
                    }

                    // 下面都是用于 处理多层函数嵌套,单函数不用管
                    //调用之前PassthroughDiscovery的污染结果，看当前调用到的类是否可以污染，如果可以污染,就把污染参数传递给高一层
                    Set<Integer> passthrough = Constant.passthroughDataflow.get(new MethodReference.Handle(owner, name, desc));
                    if (passthrough != null && !passthrough.isEmpty()) {
                        for (Integer passthroughDataflowArg : passthrough) {
                            resultTaint.addAll(argTaint.get(passthroughDataflowArg));
                        }
                    }

                    // 前面已做逆拓扑，调用链最末端最先被visit，因此，调用到的方法必然已被visit分析过
                    Map<String, Set<Integer>> evilMethodDataflow = EvilDataflow.get(new MethodReference.Handle(owner, name, desc));
                    if (evilMethodDataflow != null && !evilMethodDataflow.isEmpty()) {
                        for (String evilType : evilMethodDataflow.keySet()) {
                            Set<Integer> taints = new HashSet<>();
                            Set<Integer> evilMethodDataflowArgList = evilMethodDataflow.get(evilType);
                            if (evilMethodDataflowArgList != null && !evilMethodDataflowArgList.isEmpty()) {
                                for (Integer evilMethodDataflowArg : evilMethodDataflowArgList) {
                                    //表示argTaint.get(new Integer(evilMethodDataflowArg))里的那个值对应的参数能污染到危险方法
                                    Set<Integer> tmpTaints = argTaint.get(evilMethodDataflowArg);
                                    taints.addAll(tmpTaints);
                                }
                            }
                            toEvilTaint.put(evilType, taints);
                        }
                        //如果大于0表示调用方法可以污染到被调用方法
                        for (String evilType : toEvilTaint.keySet()) {
                            Set<Integer> tains = toEvilTaint.get(evilType);
                            // 如果调用方法为_jspService，并且污染值在第一位(request参数是_jspService方法第一位，说明恶意类可以被request污染--也就是攻击者可控)
                            if (this.name.equals("_jspService") && tains.contains(1)) {
                                //printEvilMessage中如果包含1，则表示该类已经被标记为webshell，并且已经输出告警。如果包含1的话则不要再重复输出告警了。
                                if (!printEvilMessage.contains(1)) {
                                    printEvilMessage.add(1);
                                    String msg;
                                    if (evilType.equals("Behinder")) {
                                        msg = "[+] " + "(检测结果: 恶意) " + Constant.classNameToJspName.get(classFileName) + "------该文件所调用的ClassLoader.defineClass可被request污染，疑似冰蝎/哥斯拉/天蝎webshell";
                                    } else {
                                        msg = "[+] " + "(检测结果: 恶意) " + Constant.classNameToJspName.get(classFileName) + "   " + evilType + "可被request污染，该文件为webshell!!!";
                                    }
                                    logger.info(msg);
                                    Constant.evilClass.add(classFileName);
                                    Constant.msgList.add(msg);
                                }
                            }
                        }
                    }
                    break;
                default:
                    throw new IllegalStateException("Unexpected value: " + opcode);
            }

            // 下面的switch判断是要开始 处理污点断点分析结果 (上面分析完毕了,该进行输出结果了)
            boolean isSuccessExec = false;
            switch (opcode) {
                case Opcodes.INVOKEINTERFACE:
                    InvokeInterface.analysis(owner, name, desc, itf, this, argTaint, printEvilMessage, classFileName, toEvilTaint, this.isDelete);
                    break;
                case Opcodes.INVOKEVIRTUAL:
                    isSuccessExec = InvokeVirtual.analysis(opcode, owner, name, desc, itf, this, argTaint, printEvilMessage, classFileName, toEvilTaint, this.isDelete);
                    break;
                case Opcodes.INVOKESPECIAL:
                    isSuccessExec = InvokeSpecial.analysis(opcode, owner, name, desc, itf, this, argTaint, printEvilMessage, classFileName, toEvilTaint, this.isDelete);
                    break;
                case Opcodes.INVOKESTATIC:
                    isSuccessExec = InvokeStatic.analysis(opcode, owner, name, desc, itf, this, argTaint, printEvilMessage, classFileName, toEvilTaint, this.isDelete);
                    break;
            }
            if (isSuccessExec) {
                return;
            }
            super.visitMethodInsn(opcode, owner, name, desc, itf);
            //把调用其他方法获得的污点进行传递
            if (retSize > 0) {
                operandStack.get(retSize - 1).addAll(resultTaint);
            }
        }

        @Override
        public void visitIntInsn(int opcode, int operand) {
            if (opcode == Opcodes.BIPUSH) {
                super.visitIntInsn(opcode, operand);
                operandStack.get(0).add(operand);
                return;
            }
            super.visitIntInsn(opcode, operand);
        }


        @Override
        public void visitInsn(int opcode) {
            if (opcode == Opcodes.AASTORE) {
                Set taintList = operandStack.get(0);
                if (!taintList.isEmpty()) {
                    super.visitInsn(opcode);
                    // 这里涉及一个很坑的问题，如果是p[i]="456"+p[i]+"123"这种情况，当执行aastore指令的时候，操作栈中只有三个，super.visitInsn(Opcodes.AASTORE)一调用，栈中空了，再取 operandStack.get(0)会报错
                    if (operandStack.size() > 0) {
                        operandStack.get(0).addAll(taintList);
                    }
                    return;
                }
            }
            if (opcode == Opcodes.BASTORE) {
                Set taintList = operandStack.get(0);
                super.visitInsn(opcode);
                if (!taintList.isEmpty()) {
                    for (Object tmpObj : operandStack.get(0)) {
                        if (tmpObj instanceof ArrayList) {
                            ((ArrayList) tmpObj).addAll(taintList);
                            return;
                        }
                    }
                    ArrayList<Object> list = new ArrayList<>();
                    list.addAll(taintList);
                    operandStack.set(0, list);
                }
                return;
            }
            if (opcode == Opcodes.AALOAD) {
                //operandStack.get(1)为数组对象
                Set taintList = operandStack.get(1);
                super.visitInsn(opcode);
                if (!taintList.isEmpty()) {
                    operandStack.get(0).addAll(taintList);
                }
                return;
            }
            super.visitInsn(opcode);
        }

        @Override
        public void visitLdcInsn(Object cst) {
            if (cst instanceof String) {
                super.visitLdcInsn(cst);
                operandStack.get(0).add(cst);
                return;
            }
            super.visitLdcInsn(cst);
        }


        public void superVisitMethod(int opcode, String owner, String name, String desc, boolean itf) {
            super.visitMethodInsn(opcode, owner, name, desc, itf);
        }

    }

}

