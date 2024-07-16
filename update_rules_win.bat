@echo off
REM SPDX-License-Identifier: 0BSD
REM Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted.
REM THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE.

REM Updating OpenYara
powershell -Command "Invoke-WebRequest -Uri https://raw.githubusercontent.com/xanda/OpenYara/main/rules/OpenYara.yar -OutFile rules\OpenYara.yar"

REM Updating Yara Forge collection
powershell -Command "Invoke-WebRequest -Uri https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip -OutFile yara-forge-rules-full.zip"
powershell -Command "Expand-Archive -Path yara-forge-rules-full.zip -DestinationPath . -Force"
move packages\full\yara-rules-full.yar rules\Yara-Forge-full-ruleset.yar
del yara-forge-rules-full.zip

REM Updating NSA Cyber
powershell -Command "Invoke-WebRequest -Uri https://raw.githubusercontent.com/nsacyber/Mitigating-Web-Shells/master/core.webshell_detection.yara -OutFile rules\NSAcyber-core-rule.yar"

echo.
echo [*] Update completed
echo [*] Combine collection created in ALL_Rule.yar file
echo [*] Usage: yara -r ALL_Rule.yar \path\to\scan\
