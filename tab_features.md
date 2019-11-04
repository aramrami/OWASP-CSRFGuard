# How Does CSRF Work?

## Tags
<img src=“https://bank.com/fn?param=1”>
<iframe src=“https://bank.com/fn?param=1”>
<script src=“https://bank.com/fn?param=1”>

## Autoposting Forms
<body onload="document.forms[0].submit()">
<form method="POST" action=“https://bank.com/fn”>
   <input type="hidden" name="sp" value="8109"/>
</form>

## XmlHttpRequest
Subject to same origin policy

## Credentials Included

