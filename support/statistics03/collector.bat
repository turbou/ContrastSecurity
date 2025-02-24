@echo off
call "C:\Users\turbou\git\ContrastSecurity\support\statistics03\sample_venv\Scripts\activate"
python C:\Users\turbou\git\ContrastSecurity\support\statistics03\collector.py --app_filter PetClinic_8001_Taka
deactivate
