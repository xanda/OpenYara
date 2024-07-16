#
#  SPDX-License-Identifier: 0BSD
#
#  Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted.
#
#  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE.
#

#!/bin/bash

//Updating OpenYara
wget https://raw.githubusercontent.com/xanda/OpenYara/main/rules/OpenYara.yar
mv OpenYara.yar rules/OpenYara.yar

// Updating Yara Forge collection
wget https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip
unzip -j yara-forge-rules-full.zip "packages/full/yara-rules-full.yar"
mv yara-rules-full.yar rules/Yara-Forge-full-ruleset.yar
rm yara-forge-rules-full.zip

//Updating NSA Cyber
wget https://raw.githubusercontent.com/nsacyber/Mitigating-Web-Shells/master/core.webshell_detection.yara
mv core.webshell_detection.yara rules/NSAcyber-core-rule.yar


echo ""
echo "[*] Update completed"
echo "[*] Combine collection created in ALL_Rule.yar file"
echo "[*] Usare: yara -r ALL_Rule.yar /path/to/scan/"
