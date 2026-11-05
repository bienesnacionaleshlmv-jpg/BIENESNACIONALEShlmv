@echo off
chcp 65001 >nul
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (py -3 herramientas\iniciar_publicado.py) else (python herramientas\iniciar_publicado.py)
pause
