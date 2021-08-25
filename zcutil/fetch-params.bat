@ECHO OFF
SET PROCESS_NAME=fetch-zparams
TASKLIST /V /NH /FI "imagename eq cmd.exe"| FIND /I /C "%PROCESS_NAME%" > Nul
IF %errorlevel%==0 exit 1
TITLE %PROCESS_NAME%

SETLOCAL EnableDelayedExpansion
SET ZPARAMS=(sprout-proving.key sprout-verifying.key sapling-spend.params sapling-output.params sprout-groth16.params)
SET sprout-proving.key=8bc20a7f013b2b58970cddd2e7ea028975c88ae7ceb9259a5344a16bc2c0eef7
SET sprout-verifying.key=4bd498dae0aacfd8e98dc306338d017d9c08dd0918ead18172bd0aec2fc5df82
SET sapling-spend.params=8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13
SET sapling-output.params=2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4
SET sprout-groth16.params=b685d700c60328498fbde589c8c7c484c722b788b265b72af448a5bf0ee55b50
SET "ZPARAMS_DIR=%APPDATA%\ZcashParams"
SET ZPARAMS_URL=https://verus.io/zcparams


CALL :MAIN
CD "!ZPARAMS_DIR!"
START .
PAUSE
EXIT 0


:MAIN
ECHO This script will fetch the Zcash zkSNARK parameters and verify their
ECHO integrity with sha256sum.
ECHO If they already exist locally, it will exit now and do nothing else.

SET "DOWNLOAD_CMD="
FOR %%x IN (CURL.EXE BITSADMIN.EXE) DO IF NOT [%%~$PATH:x]==[] IF NOT DEFINED DOWNLOAD_CMD SET "DOWNLOAD_CMD=FETCH_%%x"

IF NOT EXIST "!ZPARAMS_DIR!" (
	MD "!ZPARAMS_DIR!"
	(
	ECHO This directory stores common Zcash zkSNARK parameters. Note that it is
	ECHO distinct from the daemon's -datadir argument because the parameters are
	ECHO large and may be shared across multiple distinct -datadir's such as when
	ECHO setting up test networks.
	)>"!ZPARAMS_DIR!\README.txt"
)

CALL :FETCH_PARAMS
PAUSE
EXIT 0

:FETCH_BITSADMIN.EXE
SET "filename=%~1"
SET "URL=%~2"
CALL bitsadmin /transfer "Downloading !filename!" /priority FOREGROUND /download "!URL!/!filename!" "!Temp!\!filename!"
GOTO :EOF

:FETCH_CURL.EXE
SET "filename=%~1"
SET "URL=%~2"
curl -# -L -C - "%URL%/%filename%" -o "!Temp!/!filename!"
GOTO :EOF

:FETCH_PARAMS
FOR %%F IN %ZPARAMS% DO (
 	IF NOT EXIST "!ZPARAMS_DIR!\%%F"  (
        ECHO Downloading %%F
            CALL :!DOWNLOAD_CMD! "%%F" "!ZPARAMS_URL!"
            SET "filehash="
            CALL :GET_SHA256SUM "!Temp!\%%F" filehash
            IF NOT "!filehash!"=="!%%F!" (
        		ECHO Failed to verify parameter checksums!
			    DEL "!Temp!\%%F"
			    PAUSE
        		EXIT 1
        	) ELSE (
			MOVE "!Temp!\%%F" "!ZPARAMS_DIR!" >Nul
		)
    )
)
GOTO :EOF

:GET_SHA256SUM
SET "file=!%~1!"
SET "sha256sum="
FOR /f "skip=1 tokens=* delims=" %%# IN ('certutil -hashfile !file! SHA256') DO (
    IF NOT DEFINED sha256sum (
        FOR %%Z IN (%%#) DO SET "sha256sum=!sha256sum!%%Z"
    )
)
SET "%~2=!sha256sum!"
GOTO :EOF
