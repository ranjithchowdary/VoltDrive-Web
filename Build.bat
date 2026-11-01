@echo off
setlocal
if not exist backend\out mkdir backend\out
javac --release 21 -d backend\out backend\src\VoltDriveServer.java
if errorlevel 1 exit /b 1
echo VoltDrive Web backend compiled.
