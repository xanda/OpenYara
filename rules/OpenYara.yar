/*
 * SPDX-License-Identifier: 0BSD
 * 
 * Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE.
*/

rule webshell_PHP_ID_UploaderBypass {
        meta:
                description = "Webshell Uploader Bypass"
                license = "This YARA rule set is licensed under the 0BSD license. https://opensource.org/licenses/0BSD"
                author = "Adnan (xanda) Mohd Shukor"
                date = "2024-07-13"
        strings:
                $s1 = "<?php" nocase fullword ascii
                $s2 = "<title><?= $bd[0] ?></title>" fullword ascii
                $s3 = "name=\"uploadfile[]\"" fullword ascii
                $s4 = "count($_FILES['uploadfile']['name']);" fullword ascii
                $s5 = "alert alert-danger" fullword ascii
                $s6 = "Upload $i Files Successfully!" fullword ascii
        condition:
                all of them
}

rule webshell_PHP_ID_FierzaXploit_Shell {
        meta:
                description = "Webshell FierzaXploit Shell"
                license = "This YARA rule set is licensed under the 0BSD license. https://opensource.org/licenses/0BSD"
                author = "Adnan (xanda) Mohd Shukor"
                date = "2024-07-13"
        strings:
//                $s1 = "<?php" nocase fullword ascii
                $s2 = "$QUERY_STRING_UNESCAPED" fullword ascii
                $s3 = "var=\"inc\" value=\"pwd\"" fullword ascii
                $s4 = "onclick=\"fex()\"" fullword ascii
                $s5 = "exec cmd=$shl" fullword ascii
                $s6 = "FierzaXploit" fullword ascii
        condition:
                all of them
}

rule webshell_PHP_ID_SmokerBackdoor {
        meta:
                description = "Webshell Smoker Backdoor"
                license = "This YARA rule set is licensed under the 0BSD license. https://opensource.org/licenses/0BSD"
                author = "Adnan (xanda) Mohd Shukor"
                date = "2024-07-13"
        strings:
                $s1 = "<?php" nocase fullword ascii
                $s2 = "Smoker Backdoor" fullword ascii
                $s3 = "php_uname(" ascii
                $s4 = "goto" fullword ascii
                $s5 = "htmlspecialchars(file_get_contents($_GET[file]))" fullword ascii
                $s6 = "getcwd()" fullword ascii
        condition:
                all of them
}

rule webshell_PHP_ID_ShellScanner {
        meta:
                description = "Webshell Shell-Scanner"
                license = "This YARA rule set is licensed under the 0BSD license. https://opensource.org/licenses/0BSD"
                author = "Adnan (xanda) Mohd Shukor"
                date = "2024-07-13"
        strings:
                $s1 = "<?php" nocase fullword ascii
                $s2 = "Shell-Scanner" fullword ascii
                $s3 = "Start Scanning" fullword ascii
                $s4 = "$to_scan[" ascii
                $s5 = "milw0rm" ascii
                $s6 = "shell_exec" ascii
        condition:
                all of them
}

rule webshell_PHP_ID_shellfinder {
        meta:
                description = "Webshell shellfinder"
                license = "This YARA rule set is licensed under the 0BSD license. https://opensource.org/licenses/0BSD"
                author = "Adnan (xanda) Mohd Shukor"
                date = "2024-07-13"
        strings:
                $s1 = "<?php" nocase fullword ascii
                $s2 = "Website Shell Finder" fullword ascii
                $s3 = "$_POST[\"scan\"]" fullword ascii
                $s4 = "$_POST['traget']" fullword ascii
                $s5 = "$shells" fullword ascii 
                $s6 = "$suck" fullword ascii
		$s7 = "get_headers(" fullword ascii
        condition:
                all of them
}


rule webshell_PHP_ID_shellbca {
        meta:
                description = "Webshell ShellBCA"
                license = "This YARA rule set is licensed under the 0BSD license. https://opensource.org/licenses/0BSD"
                author = "Adnan (xanda) Mohd Shukor"
                date = "2024-07-13"
        strings:
                $s1 = "<?php" nocase fullword ascii
                $s2 = "$_SERVER[\"PHP_AUTH_PW\"]" fullword ascii
                $s3 = "UPLOAD SUCCES BRO" fullword ascii
                $s4 = "$_SERVER['SERVER_NAME']" fullword ascii
                $s5 = "max_execution_time" fullword ascii
                $s6 = "chmod" fullword ascii
        condition:
                all of them
}

rule webshell_PHP_ID_RansomWeb {
        meta:
                description = "Webshell RansomWeb"
                license = "This YARA rule set is licensed under the 0BSD license. https://opensource.org/licenses/0BSD"
                author = "Adnan (xanda) Mohd Shukor"
                date = "2024-07-13"
        strings:
                $s1 = "<?php" nocase fullword ascii
                $s2 = "RansomWeb Kelelawar Cyber Team" fullword ascii
                $s3 = "kelelawarcyberteam" fullword ascii
                $s4 = "htaccess(BackUp)" fullword ascii
                $s5 = "base64_decode(" fullword ascii
                $s6 = "eval(" fullword ascii
        condition:
                all of them
}

rule webshell_PHP_ID_omestpriv8_minishell {
        meta:
                description = "Webshell omestpriv8-V2_minishell"
                license = "This YARA rule set is licensed under the 0BSD license. https://opensource.org/licenses/0BSD"
                author = "Adnan (xanda) Mohd Shukor"
                date = "2024-07-13"
        strings:
                $s1 = "<?php" nocase fullword ascii
                $s2 = "$_SESSION['pass'] = $pass;" ascii
                $s3 = "$errorforbidden" fullword ascii
                $s4 = "$_SERVER['PHP_SELF']" fullword ascii
                $s5 = "ErrorDocument" fullword ascii
                $s6 = "session_start();" fullword ascii
        condition:
                all of them
}

rule webshell_PHP_ID_MassFucker {
        meta:
                description = "Webshell Mass Fucker"
                license = "This YARA rule set is licensed under the 0BSD license. https://opensource.org/licenses/0BSD"
                author = "Adnan (xanda) Mohd Shukor"
                date = "2024-07-13"
        strings:
                $s1 = "<?php" nocase fullword ascii
                $s2 = "MASS DEFACER SCRIPT" nocase fullword ascii
                $s3 = "BULUNAMADI" fullword ascii
                $s4 = "DIZIN DEGIL" fullword ascii
                $s5 = "getcwd" fullword ascii
                $s6 = "php_uname()" fullword ascii
        condition:
                all of them
}



rule webshell_PHP_ID_gecko_new {
        meta:
                description = "Webshell gecko-new"
                license = "This YARA rule set is licensed under the 0BSD license. https://opensource.org/licenses/0BSD"
                author = "Adnan (xanda) Mohd Shukor"
                date = "2024-07-13"
        strings:
                $s1 = "<?php" nocase fullword ascii
                $s2 = "$default_action = \"FilesMan\";" fullword ascii
                $s3 = "(!isset($_SESSION[md5($_SERVER['HTTP_HOST'])]))" ascii
                $s4 = "login_shell();" fullword ascii
                $s5 = "ob_clean();" fullword ascii
                $s6 = "download(" ascii
        condition:
                all of them
}

rule webshell_PHP_ID_EviLTwiNMinishell {
        meta:
                description = "Webshell EviL TwiN Minishell"
                license = "This YARA rule set is licensed under the 0BSD license. https://opensource.org/licenses/0BSD"
                author = "Adnan (xanda) Mohd Shukor"
                date = "2024-07-13"
        strings:
                $s1 = "<?php" nocase fullword ascii
                $s2 = "EviL TwiN Minishell" fullword ascii
                $s3 = "$eviltwin" fullword ascii
                $s4 = "b374k" fullword ascii
                $s5 = "eval(gzinflate(base64_decode(" fullword ascii
                $s6 = "$_POST['eviltwin']" fullword ascii
        condition:
                5 of them
}

import "pe"
rule webshell_PHP_GLOBAL_LAZY_rule_possible_webshell {
        meta:
                description = "Lazy rule - Possible Webshell"
                license = "This YARA rule set is licensed under the 0BSD license. https://opensource.org/licenses/0BSD"
                author = "Adnan (xanda) Mohd Shukor"
                date = "2024-07-13"
        strings:
                $h1 = "<?php" nocase fullword ascii
		$h2 = "<?=" ascii

		$s1 = "eval(htmlspecialchars_decode(urldecode(base64_decode(" ascii
                $s2 = "eval(base64_decode(base64_decode(" ascii
		$s3 = "eval(htmlspecialchars_decode(gzinflate(base64_decode(" ascii
                $s4 = "eval(str_rot13(gzinflate(str_rot13(base64_decode(" ascii
                $s5 = "Obfuscation provided by GladiusPHP" fullword ascii
                $s6 = "gzuncompress(base64_decode(" ascii
		$s7 = "/***88888***/@/*!12345*/NULL;$pw=" ascii
		$s8 = "eval(eval(eval(" ascii
		$s9 = "eval(htmlspecialchars_decode(base64_decode(" ascii
		$s10 = "base64_decode(urldecode(base64_decode(" ascii
		$s11 = "XJung2722 SHELL" ascii
		$s12 = "CrystalShell" ascii
		$s13 = "Cylul007 Webshell" ascii
		$s14 = /Evi[Ll] Twi[Nn] (Mini)?[sS]hell/ ascii
		$s15 = "?>fierzashell<?" ascii
		$s16 = /echo \"Backconnect source: https:\/\/github\.com\/MadExploits\/Reverse\-Shell\-Payload\\n\";/ ascii
		$s17 = /\/\/ PastiGanteng V[0-9\.]+ Shell/ ascii
        condition:
//                pe.is_pe and
//	        filename matches /(php|phtml|phar)/i) and
		filesize < 5000000 and
		($h1 or $h2) and
		(1 of ($s*) )
}


rule webshell_PHP_ID_ShellBypass {
        meta:
                description = "Webshell Shell~Bypass"
                license = "This YARA rule set is licensed under the 0BSD license. https://opensource.org/licenses/0BSD"
                author = "Adnan (xanda) Mohd Shukor"
                date = "2024-07-13"
        strings:
                $s1 = "<?php" nocase fullword ascii
                $s2 = "Change Name Gagal !!" ascii
                $s3 = "$_SERVER['REMOTE_ADDR']" ascii
                $s4 = "gethostbyname($_SERVER['HTTP_HOST'])" ascii
                $s5 = "php_uname()" ascii
                $s6 = "getcwd();" fullword ascii
        condition:
                all of them
}

rule webshell_PHP_GLOBAL_Possible_Webshell_functions {
        meta:
                description = "Possible Webshell functions"
                license = "This YARA rule set is licensed under the 0BSD license. https://opensource.org/licenses/0BSD"
                author = "Adnan (xanda) Mohd Shukor"
                date = "2024-07-13"
        strings:
                $s1 = "<?php" nocase fullword ascii
                $s2 = "posix_getpwuid" ascii
                $s3 = "Chmod" nocase ascii
                $s4 = "d0mains" ascii
                $s5 = "file_get_contents" ascii
                $s6 = "php_uname" ascii
		$s7 = "phpinfo" nocase ascii
		$s8 = "gethostbyname" nocase ascii
        condition:
                6 of them
}

rule webshell_PHP_ID_doEvil {
        meta:
                description = "Webshell doEvil"
                license = "This YARA rule set is licensed under the 0BSD license. https://opensource.org/licenses/0BSD"
                author = "Adnan (xanda) Mohd Shukor"
                date = "2024-07-13"
        strings:
                $s1 = "<?php" nocase fullword ascii
                $s2 = "function _doEvil(" ascii
                $s3 = "$toRootFopen" fullword ascii
                $s4 = "$toRootExec" fullword ascii
                $s5 = "$rootShellUrl" fullword ascii
                $s6 = "[OK!]" ascii
        condition:
                all of them
}

rule webshell_PHP_ID_AnonSecTeam2 {
        meta:
		description = "Webshell Anonsec Team"
                license = "This YARA rule set is licensed under the 0BSD license. https://opensource.org/licenses/0BSD"
                author = "Adnan (xanda) Mohd Shukor"
                date = "2024-07-13"
        strings:
                $s1 = "<?php" nocase fullword ascii
                $s2 = "$_POST['newname']" ascii
                $s3 = "$_GET['filesrc']" ascii
                $s4 = "Delete Dir Failed!" ascii
                $s5 = "Delete File Error." ascii
                $s6 = "!is_readable(\"$path/$file\"))" fullword ascii
        condition:
                all of them
}

rule webshell_PHP_ID_AnonSecTeam {
        meta:
                description = "Webshell Anonsec Team"
                license = "This YARA rule set is licensed under the 0BSD license. https://opensource.org/licenses/0BSD"
                author = "Adnan (xanda) Mohd Shukor"
                date = "2024-07-13"
        strings:
                $s1 = "<?php" nocase fullword ascii
                $s2 = "function cekdir()" fullword ascii
                $s3 = "function cekroot()" fullword ascii
                $s4 = "function dunlut" fullword ascii
                $s5 = "return $_SERVER['SERVER_NAME'];" fullword ascii
                $s6 = "$_POST['upwkwk']" ascii
        condition:
                all of them
}

rule webshell_PHP_GLOBAL_Adminer {
        meta:
                description = "Webshell or ADminer"
                license = "This YARA rule set is licensed under the 0BSD license. https://opensource.org/licenses/0BSD"
                author = "Adnan (xanda) Mohd Shukor"
                date = "2024-07-13"
        strings:
                $s1 = "<?php" nocase fullword ascii
                $s2 = "system-database.html" ascii
                $s3 = "[\"Execute at\"]" ascii
                $s4 = "$_SESSION[\"pwds\"]" ascii
                $s5 = "[\"Server Admin\"]" ascii
                $s6 = "$_POST[\"hashed\"]" ascii
        condition:
                all of them
}

rule webshell_PHP_ID_403for {
        meta:  
                description = "Webshell 403.for"
                license = "This YARA rule set is licensed under the 0BSD license. https://opensource.org/licenses/0BSD"
                author = "Adnan (xanda) Mohd Shukor"
                date = "2024-07-13"
        strings:
                $s1 = "<?php" nocase fullword ascii
		$s2 = "function komend(" fullword ascii
		$s3 = "function dunlut(" fullword ascii
		$s4 = "function cekdir(" fullword ascii
		$s5 = "htmlspecialchars(" fullword ascii
		$s6 = "set_time_limit(" fullword ascii
        condition:
                all of them
}

rule webshell_PHP_possible_webshell_eval_base64 {
        meta:
                description = "Possible Webshell due to eval base64 string"
                license = "This YARA rule set is licensed under the 0BSD license. https://opensource.org/licenses/0BSD"
                author = "Adnan (xanda) Mohd Shukor"
                date = "2024-07-13"
        strings:
                $s1 = "<?php" nocase fullword ascii
                $s2 = "base64_decode(" fullword ascii
                $s3 = "eval(" fullword ascii
        condition:
                all of them
}
