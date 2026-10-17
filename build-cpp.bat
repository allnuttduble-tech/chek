@echo off
setlocal
call "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cl /nologo /std:c++17 /EHsc /DUNICODE /D_UNICODE main.cpp user32.lib gdi32.lib advapi32.lib shell32.lib winhttp.lib bcrypt.lib /Fe:DetectAcUI.exe
if errorlevel 1 exit /b %errorlevel%
echo Built DetectAcUI.exe
