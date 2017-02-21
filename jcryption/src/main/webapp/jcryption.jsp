<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>jcryption demo</title>
</head>
<body>
	<form action="login">
		<input name="username"> <input name="password"> <input
			type="submit" value="submit">
	</form>
</body>
<script type="text/javascript" src="./resources/jquery-3.1.1.js"></script>
<script type="text/javascript" src="./resources/jquery.jcryption.3.1.0.js"></script>
<script type="text/javascript">
	$(function() {
		$.jCryption.defaultOptions.getKeysURL = "getPublickey";
		$.jCryption.defaultOptions.handshakeURL = "handshake";
		$("form").jCryption();
	});
</script>
</html>