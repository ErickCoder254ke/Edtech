@echo off
echo ========================================
echo PetSoko Backend Server - Quick Start
echo ========================================
echo.

:: Check if .env exists
if not exist ".env" (
    echo ERROR: .env file not found!
    echo.
    echo Please create backend/.env file with:
    echo   MONGO_URL=your_mongodb_connection_string
    echo   DB_NAME=petsoko
    echo   JWT_SECRET=your_secret_key
    echo.
    echo See .env.example for full configuration
    pause
    exit /b 1
)

echo Checking environment...
echo.

:: Check if virtual environment should be used
if exist "venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call venv\Scripts\activate.bat
)

echo Starting backend server...
echo.
echo Backend will be available at:
echo   http://localhost:8000
echo.
echo API Documentation:
echo   http://localhost:8000/docs
echo.
echo Health Check:
echo   http://localhost:8000/
echo.
echo Press Ctrl+C to stop
echo.
echo ========================================
echo.

uvicorn server:app --reload --host 0.0.0.0 --port 8000
