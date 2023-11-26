<%@ page import="javax.naming.Context" %>
<%@ page import="javax.naming.InitialContext" %>
<%@ page language="java" pageEncoding="UTF-8" %>
<%
    try {
        System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "true");
        String uri = "rmi://127.0.0.1:1099/hello";
        Context ctx = new InitialContext();
        ctx.lookup(uri);
    } catch (Exception e) {
        e.printStackTrace();
    }
%>