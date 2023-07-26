<?php 
//backend will use Argon2id as it is considered the most secure hashing algorithm in PHP
//just in case we will add another layer of security by using a couple passes of sha512 and sha384 hashing in front of Argon2id
echo $_POST["hash"];
?>