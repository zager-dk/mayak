@echo off
rem Сборка Маяк VPN в один файл dist\MayakVPN.exe
chcp 65001 >nul
setlocal
cd /d "%~dp0"

where dotnet >nul 2>&1
if errorlevel 1 (
  echo [1/3] .NET SDK не найден, устанавливаю .NET 8 SDK через winget...
  winget install --id Microsoft.DotNet.SDK.8 -e --accept-source-agreements --accept-package-agreements
  if errorlevel 1 goto nodotnet
  set "PATH=%PATH%;%ProgramFiles%\dotnet"
)

dotnet --list-sdks | findstr /r "^[89]\. ^1[0-9]\." >nul
if errorlevel 1 (
  echo [1/3] Нужен .NET SDK 8 или новее, устанавливаю...
  winget install --id Microsoft.DotNet.SDK.8 -e --accept-source-agreements --accept-package-agreements
  if errorlevel 1 goto nodotnet
)

echo [2/3] Самопроверка ядра...
dotnet run --project tests\Mayak.SelfTest -c Release -- samples
if errorlevel 1 goto fail

echo [3/3] Сборка MayakVPN.exe...
dotnet publish src\MayakVPN\MayakVPN.csproj -c Release -o dist
if errorlevel 1 goto fail

echo.
echo Готово: %cd%\dist\MayakVPN.exe
start "" explorer.exe "%cd%\dist"
exit /b 0

:nodotnet
echo Не удалось установить .NET SDK. Скачайте .NET 8 SDK вручную: https://dotnet.microsoft.com/download/dotnet/8.0
exit /b 1

:fail
echo Сборка завершилась с ошибкой, смотрите сообщения выше.
exit /b 1
