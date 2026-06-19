@echo off
setlocal EnableExtensions EnableDelayedExpansion

cd /d "%~dp0"

set "PRESET=x64-release"
set "CONFIG=Release"
set "BUILD_DIR=out\build\%PRESET%"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if defined VCPKG_ROOT set "USER_VCPKG_ROOT=%VCPKG_ROOT%"

echo [1/3] Preparing Visual Studio x64 build environment...
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

echo [2/3] Configuring C++ build directory if needed...
if not exist "%BUILD_DIR%\CMakeCache.txt" (
    rem Pass the toolchain explicitly because VsDevCmd can set VCPKG_ROOT to Visual Studio's bundled vcpkg.
    cmake --preset %PRESET% -DCMAKE_TOOLCHAIN_FILE="%VCPKG_TOOLCHAIN%"
    if errorlevel 1 exit /b 1
) else (
    echo CMake cache exists: %BUILD_DIR%
)

echo [3/3] Building C++ targets...
cmake --build "%BUILD_DIR%" --config %CONFIG%
if errorlevel 1 exit /b 1

for %%F in (
    "%BUILD_DIR%\host.exe"
    "%BUILD_DIR%\client.exe"
    "%BUILD_DIR%\server.exe"
    "%BUILD_DIR%\cert.exe"
    "%BUILD_DIR%\native.dll"
    "%BUILD_DIR%\datachannel.dll"
    "%BUILD_DIR%\juice.dll"
    "%BUILD_DIR%\libcrypto-3-x64.dll"
    "%BUILD_DIR%\libssl-3-x64.dll"
) do (
    if not exist "%%~F" (
        echo ERROR: Required C++ output is missing: %%~F
        exit /b 1
    )
)

echo C++ build completed successfully.
echo Outputs:
echo   %BUILD_DIR%\host.exe
echo   %BUILD_DIR%\client.exe
echo   %BUILD_DIR%\server.exe
echo   %BUILD_DIR%\cert.exe
echo   %BUILD_DIR%\native.dll
endlocal
