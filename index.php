<div>
        Input text for hashing:<br><br>
        <input type="text" id="textID" name="inputtext">
</div>
<br>
_______________________________________________________________________________________________________________________________
<br>
<br>
Hashed result:<br><br>
<div id="resultHash"></div>
<script>
        //First front end hashing with fixed pepper, there is also more robust backend hashing, which is actually the main focus of this project
        //This is just a simple example of front end hashing, and it is not the main focus of this project
        //Reason for front end hashing is to prevent transmission of the plain password over the internet,
        //the server from ever seeing the original password, and to prevent the server from knowing if two users have the same password
        //I am fully aware that attacker will completely bypass this front end hashing, but it is still a good practice to use it when regular people use the website,
        //if for example their network is compromised, or if the backend is compromised, for example a malware on the server, or a data breach
        async function sha512HashSpecial(data) {
                const pepper = '1234567890pepperForHashing';
                const encoder = new TextEncoder();
                const dataBuffer = encoder.encode(pepper + data + pepper + data + pepper);
                const hashBuffer = await crypto.subtle.digest('SHA-512', dataBuffer);

                // Convert the hash buffer to hexadecimal format
                let hashedData = '';
                const hashArray = new Uint8Array(hashBuffer);
                for (let i = 0; i < hashArray.length; i++) {
                        hashedData += hashArray[i].toString(16).padStart(2, '0');
                }

                return hashedData + hashedData;
        }

        async function sha512HashRegular(data) {
                const encoder = new TextEncoder();
                const dataBuffer = encoder.encode(data);
                const hashBuffer = await crypto.subtle.digest('SHA-512', dataBuffer);

                // Convert the hash buffer to hexadecimal format
                let hashedData = '';
                const hashArray = new Uint8Array(hashBuffer);
                for (let i = 0; i < hashArray.length; i++) {
                        hashedData += hashArray[i].toString(16).padStart(2, '0');
                }

                return hashedData;
        }
        
        async function sha384HashRegular(data) {
                const encoder = new TextEncoder();
                const dataBuffer = encoder.encode(data);
                const hashBuffer = await crypto.subtle.digest('SHA-384', dataBuffer);

                // Convert the hash buffer to hexadecimal format
                let hashedData = '';
                const hashArray = new Uint8Array(hashBuffer);
                for (let i = 0; i < hashArray.length; i++) {
                        hashedData += hashArray[i].toString(16).padStart(2, '0');
                }

                return hashedData;
        }

        //Function intended for eliminating some voulnerabilities of SHA-512 hashing,
        //as well as adding some execution time to make brute force attacks harder
        async function mainHashingWrapper(text) {
                var hashedResult = text;
                
                /////////////////////////////////////////////////////////////////////////

                //First part of hashing

                var hashedResultPart1 = '',
                        hashedResultPart2 = '';
                for (var increment = 0; increment < 1000; increment++) {
                        await sha512HashSpecial(hashedResult).then((hashedData) => {
                                hashedResult = hashedData;
                        });
                }

                hashedResultPart1 = hashedResult;

                for (var increment = 0; increment < 1000; increment++) {
                        await sha512HashSpecial(hashedResult).then((hashedData) => {
                                hashedResult = hashedData;
                        });
                }

                for (var increment = 0; increment < 1000; increment++) {
                        await sha512HashRegular(hashedResult).then((hashedData) => {
                                hashedResult = hashedData + hashedData;
                        });
                }

                hashedResultPart2 = hashedResult;

                /////////////////////////////////////////////////////////////////////////

                //Second part of hashing

                for (var increment = 0; increment < 50; increment++) {
                        await sha384HashRegular(hashedResultPart1).then((hashedData) => {
                                hashedResultPart1 = hashedData;
                        });
                }

                for (var increment = 0; increment < 50; increment++) {
                        await sha384HashRegular(hashedResultPart2).then((hashedData) => {
                                hashedResultPart2 = hashedData;
                        });
                }

                /////////////////////////////////////////////////////////////////////////

                //Third part of hashing

                var hashedResultPart3 = hashedResultPart1 + "fixedPepper1" + hashedResultPart1;

                var hashedResultPart4 = hashedResultPart2 + "fixedPepper2" + hashedResultPart2;

                var hashedResultPart5 = hashedResultPart1 + "fixedPepper3" + hashedResultPart2;

                var hashedResultPart6 = hashedResultPart2 + "fixedPepper4" + hashedResultPart1;

                var frontEndSalt1 = "-salt1-<?php echo hash('sha256', time() . "1"); ?>";
                var frontEndSalt2 = "-salt2-<?php echo hash('sha256', time() . "2"); ?>";
                var frontEndSalt3 = "-salt3-<?php echo hash('sha256', time() . "3"); ?>";
                var frontEndSalt4 = "-salt4-<?php echo hash('sha256', time() . "4"); ?>";
                
                //Hash with front end salt so that the same passwords typed twice in a row will have different hashes,
                //this protects against rainbow table attacks and against stealing passwords in transit if ssl is compromised or not used,
                //or if there is some sort of malware in the clients network that steals passwords in transit
                for (var increment = 0; increment < 50; increment++) {
                        await sha512HashRegular(hashedResultPart3).then((hashedData) => {
                                hashedResultPart3 = hashedData + frontEndSalt1;
                        });
                }
                for (var increment = 0; increment < 50; increment++) {
                        await sha512HashRegular(hashedResultPart4).then((hashedData) => {
                                hashedResultPart4 = hashedData + frontEndSalt2;
                        });
                }
                for (var increment = 0; increment < 50; increment++) {
                        await sha512HashRegular(hashedResultPart5).then((hashedData) => {
                                hashedResultPart5 = hashedData + frontEndSalt3;
                        });
                }
                for (var increment = 0; increment < 50; increment++) {
                        await sha512HashRegular(hashedResultPart6).then((hashedData) => {
                                hashedResultPart6 = hashedData + frontEndSalt4;
                        });
                }

                //Another saltless hashing
                for (var increment = 0; increment < 10; increment++) {
                        await sha512HashRegular(hashedResultPart3).then((hashedData) => {
                                hashedResultPart3 = hashedData;
                        });
                }
                for (var increment = 0; increment < 10; increment++) {
                        await sha512HashRegular(hashedResultPart4).then((hashedData) => {
                                hashedResultPart4 = hashedData;
                        });
                }
                for (var increment = 0; increment < 10; increment++) {
                        await sha512HashRegular(hashedResultPart5).then((hashedData) => {
                                hashedResultPart5 = hashedData;
                        });
                }
                for (var increment = 0; increment < 10; increment++) {
                        await sha512HashRegular(hashedResultPart6).then((hashedData) => {
                                hashedResultPart6 = hashedData;
                        });
                }
                
                hashedResult = hashedResultPart3 + hashedResultPart4 + hashedResultPart5 + hashedResultPart6 + frontEndSalt1 + frontEndSalt2 + frontEndSalt3 + frontEndSalt4;

                return hashedResult;
        }

        //main call for hashing
        async function hashThisText(textForHashing) {
                var finalHashedResult = '';
                await mainHashingWrapper(textForHashing).then((finalHashedData) => {
                        finalHashedResult = finalHashedData;
                });
                return finalHashedResult;
        }
        
        var inputText = document.getElementById("textID").value;
        ////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////
        //MAIN CALL FOR HASHING TO THE SERVER
        //MAIN CALL FOR HASHING TO THE SERVER
        //MAIN CALL FOR HASHING TO THE SERVER
        hashThisText(inputText).then((hashedData) => {
                //this is now ready to be sent to the server for backend hashing
                
                let xhr = new XMLHttpRequest();
                
                xhr.onreadystatechange = function() {
                        if (xhr.readyState === 4) {
                                if (xhr.status === 200) {
                                        document.getElementById("resultHash").innerHTML = xhr.responseText;
                                }
                        }
                }
                xhr.open('POST', 'backendHashing.php');
                xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
                xhr.send('hash=' + encodeURIComponent(hashedData)+ '&lowsecurity=<?php echo hash('sha256', time() . "1234567890lowsecurity" . $_SERVER['REMOTE_ADDR']); ?>');
        });
</script>