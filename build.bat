@echo off
cd /d "%~dp0"
dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true
pause
