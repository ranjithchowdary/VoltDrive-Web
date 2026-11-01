@echo off
call Build.bat
if errorlevel 1 exit /b 1
java -cp backend\out VoltDriveServer
