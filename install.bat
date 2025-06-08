@echo off
chcp 65001 >nul
cd /d "%~dp0"

set VENV_DIR=.venv

if not exist %VENV_DIR% (
    echo Создаю виртуальное окружение...
    python -m venv %VENV_DIR%
)

call %VENV_DIR%\Scripts\activate.bat

echo Установка зависимостей...
pip install --upgrade pip >nul
pip install -r requirements.txt
if errorlevel 1 (
    echo Ошибка установки зависимостей.
    pause
    exit /b 1
)

if not exist db_config.json (
    copy db_config.template.json db_config.json
    echo Создан файл db_config.json. Пожалуйста, отредактируйте его перед запуском.
)

echo Сборка exe через PyInstaller...
pyinstaller ^
  --onefile ^
  --distpath . ^
  --name main ^
  --hidden-import PyQt5.QtWidgets ^
  --hidden-import PyQt5.QtCore ^
  --hidden-import PyQt5.QtGui ^
  main.py

echo Готово! Запустите main.exe
pause
