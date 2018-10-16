

@echo off

msbuild AdES.sln /p:Configuration="Debug" /p:Platform=x64
copy AdES.lib AdES64d.lib
call cleanup.bat
