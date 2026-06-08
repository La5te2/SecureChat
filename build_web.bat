@echo off
setlocal EnableExtensions EnableDelayedExpansion

cd /d "%~dp0"

set "PRESET=x64-release"
set "CONFIG=Release"
set "BUILD_DIR=out\build\%PRESET%"
set "WEB_PROJECT=app\web\SecureChat.Web.csproj"
set "WEB_OBJ=app\web\obj"
set "WEB_BIN=app\web\bin"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if defined VCPKG_ROOT set "USER_VCPKG_ROOT=%VCPKG_ROOT%"

echo [1/4] Preparing Visual Studio x64 build environment...
if not defined VSCMD_VER (
    set "VSDEVCMD="
    if exist "!VSWHERE!" (
        for /f "usebackq tokens=*" %%I in (`"!VSWHERE!" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
            set "VSDEVCMD=%%I\Common7\Tools\VsDevCmd.bat"
        )
    )
    if not defined VSDEVCMD if exist "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" set "VSDEVCMD=C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
    if not defined VSDEVCMD if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" set "VSDEVCMD=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
    if not defined VSDEVCMD (
        echo ERROR: Visual Studio C++ build tools were not found.
        exit /b 1
    )
    call "!VSDEVCMD!" -arch=x64
    if errorlevel 1 exit /b 1
) else (
    echo Visual Studio environment already active.
)

if not defined USER_VCPKG_ROOT (
    echo ERROR: VCPKG_ROOT is not set.
    echo Set VCPKG_ROOT to your vcpkg checkout, then reopen the terminal. Example:
    echo   setx VCPKG_ROOT D:\Tools\vcpkg
    exit /b 1
)
set "VCPKG_ROOT=%USER_VCPKG_ROOT%"
set "VCPKG_TOOLCHAIN=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake"
if not exist "%VCPKG_TOOLCHAIN%" (
    echo ERROR: vcpkg toolchain file was not found:
    echo   %VCPKG_TOOLCHAIN%
    exit /b 1
)
echo Using vcpkg root: %VCPKG_ROOT%

echo [2/4] Configuring C++ build directory if needed...
if not exist "%BUILD_DIR%\CMakeCache.txt" (
    rem Pass the toolchain explicitly because VsDevCmd can set VCPKG_ROOT to Visual Studio's bundled vcpkg.
    cmake --preset %PRESET% -DCMAKE_TOOLCHAIN_FILE="%VCPKG_TOOLCHAIN%"
    if errorlevel 1 exit /b 1
) else (
    echo CMake cache exists: %BUILD_DIR%
)

echo [3/4] Building C++ native library...
cmake --build "%BUILD_DIR%" --config %CONFIG%
if errorlevel 1 exit /b 1

for %%F in (
    "%BUILD_DIR%\native.dll"
    "%BUILD_DIR%\datachannel.dll"
    "%BUILD_DIR%\juice.dll"
    "%BUILD_DIR%\libcrypto-3-x64.dll"
    "%BUILD_DIR%\libssl-3-x64.dll"
) do (
    if not exist "%%~F" (
        echo ERROR: Required native output is missing: %%~F
        exit /b 1
    )
)

echo [4/4] Building SecureChat Web for Windows...
if not exist "%WEB_BIN%" mkdir "%WEB_BIN%"
if exist "C:\Program Files\dotnet\dotnet.exe" (
    "C:\Program Files\dotnet\dotnet.exe" build "%WEB_PROJECT%" -c %CONFIG% -r win-x64 --self-contained false
) else (
    dotnet build "%WEB_PROJECT%" -c %CONFIG% -r win-x64 --self-contained false
)
if errorlevel 1 exit /b 1

if exist "%WEB_OBJ%" (
    echo Cleaning C# intermediate directory: %WEB_OBJ%
    rd /s /q "%WEB_OBJ%"
)

echo Web build completed successfully.
echo Run with:
echo   dotnet app\web\bin\%CONFIG%\net10.0\win-x64\SecureChat.Web.dll
endlocal
