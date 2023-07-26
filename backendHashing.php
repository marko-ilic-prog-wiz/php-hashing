<?php
require_once 'TextHasher.php';
//backend will use Argon2id as it is considered the most secure hashing algorithm in PHP
//just in case we will add another layer of security by using a couple passes of sha512 and sha384 hashing in front of Argon2id

//benefits of using front end hashing are:
//1. that the server will never see the original password, only the hashed version, eliminating the possibility of a data breach in case of a malware or malicious employee
//2. that the character set will be limited to the character set of the front end hashing algorithm
//3. that the server will not be able to tell if two users have the same password
//4. that there is a fixed length of the front end hash, preventing too short or too long requests
//5. that the plain password won't be transmitted over the internet

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!isset($_POST["hash"]) || !isset($_POST["lowsecurity"])) {
                exit;
        }
        if (strlen($_POST["lowsecurity"]) != 64) {
                exit;
        }
        if (strlen($_POST["hash"]) != 796) {
                exit;
        }
        $textHasher = new TextHasher($_POST["hash"],$_POST["lowsecurity"]);
        
        echo $textHasher->getHash();
}