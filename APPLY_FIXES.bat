@echo off
setlocal
cd /d "%~dp0"
python apply_threatmap_fixes.py .
if errorlevel 1 (
  echo.
  echo Patch failed. Review the error above; no silent changes were made.
  exit /b 1
)
echo.
echo Patch completed. Run git diff and the tests listed in README.md.
endlocal
