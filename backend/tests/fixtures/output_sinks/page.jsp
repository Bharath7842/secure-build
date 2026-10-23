<%@ page contentType="text/html" %>
<html>
<body>
<% String q = request.getParameter("q");
   out.println(q); %>
<p>Total: <%= request.getParameter("n") %></p>
</body>
</html>
