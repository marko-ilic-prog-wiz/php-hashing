<?php
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
        //lowsecurity will be 60 seconds, just to make it harder for a brute force attack,
        //also we are including the IP in the lowsecurity hash to make it harder for botnet attacks from multiple ips
        $currentTime = time();
        $passedLowSecurity = false;
        for ($timeCounter = $currentTime - 60; $timeCounter <= $currentTime; $timeCounter++) {
                $lowSecurityHash = hash('sha256', $timeCounter . "1234567890lowsecurity" . $_SERVER['REMOTE_ADDR']);
                if ($lowSecurityHash == $_POST["lowsecurity"]) {
                        $passedLowSecurity = true;
                }
        }
        if ($passedLowSecurity === false) {
                exit;
        }

        //time for some checks for the main hash to see if it only contains alphanumeric characters
        $mainHash = $_POST["hash"];
        $mainHash = str_replace(" ", "", $mainHash);
        $mainHash = str_replace("\n", "", $mainHash);
        $mainHash = str_replace("\r", "", $mainHash);
        $mainHash = str_replace("\t", "", $mainHash);
        $mainHash = str_replace("\f", "", $mainHash);
        $mainHash = str_replace("\v", "", $mainHash);
        $mainHash = str_replace("\0", "", $mainHash);
        $mainHash = str_replace("\x0B", "", $mainHash);
        
        if (strlen($mainHash) != 796) {
                exit;
        }

        if (isAllowedString($mainHash) === false) {
                echo "not allowed";
                exit;
        }
        
        //now we can start the backend hashing
        
        
        
        echo $_POST["hash"];
}

function isAllowedString($stringInQuestion)
{
        return preg_match('/^[0-9a-z-]+$/', $stringInQuestion) === 1;
}
