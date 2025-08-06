@echo off
echo.
echo ╦═╗┌─┐┌┬┐╔═╗┌─┐┌┐┌┌┬┐┬┌┐┌┌─┐┬    ╔═╗╦
echo ╠╦╝├┤  ││╚═╗├┤ │││ │ ││││├┤ │    ╠═╣║
echo ╩╚═└─┘─┴┘╚═╝└─┘┘└┘ ┴ ┴┘└┘└─┘┴─┘  ╩ ╩╩
echo     AI-Powered Ethical Hacking Agent
echo.

if "%1"=="" (
    echo Usage: redsentinel.bat [options]
    echo.
    echo Examples:
    echo   redsentinel.bat --url https://example.com --level standard
    echo   redsentinel.bat --ip 192.168.1.1 --level basic
    echo   redsentinel.bat --list-tools
    echo   redsentinel.bat --help
    echo.
    pause
    exit /b
)

python redsentinel.py %*
