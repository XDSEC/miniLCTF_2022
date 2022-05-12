<%--
  Created by IntelliJ IDEA.
  User: wanan
  Date: 2022/4/29
  Time: 上午9:18
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="s" uri="/struts-tags" %>
<html>
<head>
    <title>A Simple Album</title>
</head>
<body>
<h2>Hi ${username},you can view some photos by giving me the id.(you can add 1,2,... after the id to get more photos)</h2>
<br>
<s:a id="%{id}" href="%{link}">Go to see the photo!</s:a>
</body>
</html>
