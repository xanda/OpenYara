@echo off
REM SPDX-License-Identifier: 0BSD
REM
REM Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted.
REM
REM THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE.

REM Check if two arguments are provided
if "%~2"=="" (
    echo Usage: %~nx0 ^<rules_file^> ^<path_to_scan^>
    exit /b 1
)

REM Assign arguments to variables
set "rules_file=%~1"
set "path_to_scan=%~2"

REM Execute yara and save the output to a variable
for /f "delims=" %%i in ('yara "%rules_file%" "%path_to_scan%"') do set "yara_output=%%i"

REM Create a temporary file to store unique file paths
set "temp_file=%TEMP%\tempfile.txt"

REM Extract unique file paths from yara output
echo %yara_output% | findstr /r /o /c:"[^\ ]*" | sort | uniq > "%temp_file%"

REM Function to calculate MD5 checksum
:calculate_md5
setlocal enabledelayedexpansion
for /f "delims=" %%i in ('certutil -hashfile "%~1" MD5 ^| findstr /v "hash"') do set "md5_checksum=%%i"
endlocal & set "md5_checksum=%md5_checksum: =%"
goto :eof

REM Read each unique file path and process detections
for /f "delims=" %%i in (%temp_file%) do (
    REM Get file details using dir and for
    for /f "tokens=1,3,4,5,6,7,8" %%j in ('dir /q %%i') do (
        set "file_path=%%i"
        set "user=%%k"
        set "group=%%l"
        set "filetimestamp=%%m %%n %%o"

        REM Get all detections for the current file path
        for /f "delims=" %%p in ('echo %yara_output% ^| findstr "%%i" ^| tr "\n" ";" ^| sed "s/;$//"') do set "detections=%%p"

        REM Calculate MD5 checksum
        call :calculate_md5 "%%i"

        REM Print the CSV line
        echo %%i,%%k,%%l,%%m %%n %%o,%%p,!md5_checksum!
    )
)

REM Remove the temporary file
del "%temp_file%"

