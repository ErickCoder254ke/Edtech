@echo off
REM PetSoko Admin Seeding Script - Windows Batch File
REM Quick launcher for seed_admin.py

echo ====================================
echo PetSoko Admin Seeding Tool
echo ====================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher
    pause
    exit /b 1
)

echo Python found. Starting seed script...
echo.

REM Check for command line arguments
if "%1"=="" (
    echo No arguments provided. Creating admin only...
    echo.
    python seed_admin.py
) else if "%1"=="clean" (
    echo Running in CLEAN mode...
    echo.
    if "%2"=="sample" (
        python seed_admin.py --clean --with-sample
    ) else (
        python seed_admin.py --clean
    )
) else if "%1"=="sample" (
    echo Creating admin with sample data...
    echo.
    python seed_admin.py --with-sample
) else (
    echo Unknown argument: %1
    echo.
    echo Usage:
    echo   run_seed.bat              - Create admin only
    echo   run_seed.bat sample       - Create admin with sample data
    echo   run_seed.bat clean        - Clean database and create admin
    echo   run_seed.bat clean sample - Clean database and create all data
)

echo.
echo ====================================
pause
