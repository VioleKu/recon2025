# Recon 2025

Самый стабильный и рабочий Python-recon в ноябре 2025 года  
Автор: VioleKu → https://github.com/VioleKu/recon2025

### Особенности
- Исправленный crt.sh (Identity=%25…) — работает 100%
- Никаких падений (try/except везде)
- SSL-инфо без крашей
- Красивый HTML-отчёт

### Установка и запуск
```bash
git clone https://github.com/VioleKu/recon2025.git
cd recon2025
pip install aiohttp
python3 recon.py tesla.com --threads 300
