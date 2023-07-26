<?php

class TextHasher
{
        private $hash = '';
        private $lowSecurityHash = '';
        private $frontEndSalt1 = '', $frontEndSalt2 = '', $frontEndSalt3 = '', $frontEndSalt4 = '';

        public function __construct($hash, $lowSecurityHash)
        {
                //lowsecurity will be timed to 60 seconds after page load, just to make it harder for a brute force attack,
                //also we are including the IP in the lowsecurity hash to make it harder for botnet attacks from multiple ips,
                //because they first need to get this lowsecurity hash from the server
                $currentTime = time();
                $passedLowSecurity = false;
                for ($timeCounter = $currentTime - 60; $timeCounter <= $currentTime; $timeCounter++) {
                        $lowSecurityHashCheck = hash('sha256', $timeCounter . "1234567890lowsecurity" . $_SERVER['REMOTE_ADDR']);
                        if ($lowSecurityHashCheck == $lowSecurityHash) {
                                $passedLowSecurity = true;
                        }
                }
                if ($passedLowSecurity === false) {
                        exit;
                }

                //time for some checks for the main hash to see if it only contains alphanumeric characters
                $mainHash = $hash;
                //exiting before the regex check if there are some forbidden characters, basically unnecessary,
                //but would be a good point for logging to detect attacks or annomalies from the front end
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

                if ($this->isAllowedString($mainHash) === false) {
                        exit;
                }


                /////////////////////////////////////////////
                /////////////////////////////////////////////
                //we would save these salts in the database for later use in hash verification
                $frontEndSalt1 = $this->extractSalt1($mainHash);
                $frontEndSalt2 = $this->extractSalt2($mainHash);
                $frontEndSalt3 = $this->extractSalt3($mainHash);
                $frontEndSalt4 = $this->extractSalt4($mainHash);
                /////////////////////////////////////////////
                /////////////////////////////////////////////

                if (strlen($frontEndSalt1) !== 64) {
                        exit;
                }
                if (strlen($frontEndSalt2) !== 64) {
                        exit;
                }
                if (strlen($frontEndSalt3) !== 64) {
                        exit;
                }
                if (strlen($frontEndSalt4) !== 64) {
                        exit;
                }

                //after all checks we can finally safely assign the values to the class private variables
                //there are many ways these checks can be done, outside of the constuctor, but this is just one way
                //accepted way would be to use setters and getters and to expose them publicly, but this is just a simple example
                
                $this->frontEndSalt1 = $frontEndSalt1;
                $this->frontEndSalt2 = $frontEndSalt2;
                $this->frontEndSalt3 = $frontEndSalt3;
                $this->frontEndSalt4 = $frontEndSalt4;

                $this->hash = $hash;
                $this->lowSecurityHash = $lowSecurityHash;
        }

        public function getHash()
        {
                
                //now we can start the backend hashing
                $mainHash = $this->hash;
                $mainHash = hash('sha512', $mainHash);
                $mainHash = hash('sha384', $mainHash);
                
                // Specify custom Argon2id options
                $options = [
                        'memory_cost' => 65536,   // The amount of memory in bytes that Argon2id will use (default is 1024 KB)
                        'time_cost'   => 4,       // The number of iterations (default is 2)
                        'threads'     => 3,       // The number of threads to use for processing (default is 2)
                ];

                // Hash the mainHash using Argon2id with custom parameters
                $hashedMainHash = password_hash($mainHash, PASSWORD_ARGON2ID, $options);

                // Output the hashed mainHash
                //Normally we would save this in the database for later use in hash verification
                return $hashedMainHash;
        }

        private function extractSalt1($inputString)
        {
                $pattern = '/-salt1-([^-]+)-salt2-/';
                preg_match($pattern, $inputString, $matches);
                return isset($matches[1]) ? $matches[1] : exit;
        }
        private function extractSalt2($inputString)
        {
                $pattern = '/-salt2-([^-]+)-salt3-/';
                preg_match($pattern, $inputString, $matches);
                return isset($matches[1]) ? $matches[1] : exit;
        }

        private function extractSalt3($inputString)
        {
                $pattern = '/-salt3-([^-]+)-salt4-/';
                preg_match($pattern, $inputString, $matches);
                return isset($matches[1]) ? $matches[1] : exit;
        }
        
        private function extractSalt4($inputString)
        {
                $pattern = '/-salt4-([^-]+)$/';
                preg_match($pattern, $inputString, $matches);
                return isset($matches[1]) ? $matches[1] : exit;
        }

        private function isAllowedString($stringInQuestion)
        {
                return preg_match('/^[0-9a-z-]+$/', $stringInQuestion) === 1;
        }
}
