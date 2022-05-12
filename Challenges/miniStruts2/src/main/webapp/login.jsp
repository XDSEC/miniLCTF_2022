<%--
  Created by IntelliJ IDEA.
  User: wanan
  Date: 2022/5/1
  Time: 下午4:39
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib uri="/struts-tags" prefix="s" %>
<html>
<head>
    <title>login</title>
</head>
<body>
<s:form action="login.action" method="post">
    <s:textfield label="User Name" name="username"/>
    <s:textfield label="Password" name="password"/>
    <s:submit label="Login"/>
</s:form>
</body>
</html>
