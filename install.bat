@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo Установка зависимостей...
pip install -r requirements.txt
if errorlevel 1 (
    echo Ошибка установки зависимостей. Исправьте ошибки и попробуйте снова.
    pause
    exit /b 1
)

if not exist db_config.json (
    copy db_config.template.json db_config.json
    echo Создан файл db_config.json. Пожалуйста, отредактируйте его перед запуском.
)

echo Сборка exe через PyInstaller...
python -m PyInstaller --onefile main.py --distpath .

echo Готово! Запустите main.exe
pause
