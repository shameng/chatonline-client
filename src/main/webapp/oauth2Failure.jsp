<%--
  Created by IntelliJ IDEA.
  User: bang
  Date: 2017/2/8
  Time: 18:33
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<html>
<head>
    <title>失败</title>
</head>
<body>
    OAuth2登录失败了，如错误的auth code。<br/>
    <c:if test="${not empty param.error}">
        错误码：
        ${param.error}
        ${param.error_description}
    </c:if>
</body>
</html>
