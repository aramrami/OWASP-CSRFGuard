<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://www.owasp.org/index.php/Category:OWASP_CSRFGuard_Project/Owasp.CsrfGuard.tld" prefix="csrf" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>JSP Tag Token Injection</title>
</head>
<body>
<h3>Test Link(s)</h3>
<ul>
	<li><a href="protect.html?<csrf:token uri="protect.html"/>">protect.html</a></li>
	<li><a href="/protect.html?<csrf:token uri="/protect.html"/>">/protect.html</a></li>
	<li><a href="http://localhost/test.html?<csrf:token uri="http://localhost/test.html"/>">http://localhost/test.html</a></li>
	<li><a href="javascript:alert('test')">javascript:alert('test')</a></li>
</ul>
<ul>
	<li><csrf:a href="protect.html">protect.html</csrf:a></li>
	<li><csrf:a href="/protect.html">/protect.html</csrf:a></li>
</ul>
<br/>
<h3>Test Form(s)</h3>
<form id="formTest1" name="formTest1" action="protect.html">
	<input type="text" name="text" value="text"/>
	<input type="submit" name="submit" value="submit"/>
	<input type="hidden" name="<csrf:tokenname/>" value="<csrf:tokenvalue uri="protect.html"/>"/>
</form>
<csrf:form id="formTest2" name="formTest2" action="protect.html">
	<input type="text" name="text" value="text"/>
	<input type="submit" name="submit" value="submit"/>
</csrf:form>
</body>
</html>