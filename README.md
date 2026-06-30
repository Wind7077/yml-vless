# VLESS Checker

Автоматическая проверка VLESS подписок с фильтрацией по российским SNI.

## Как использовать

1. Добавьте источники подписок в файл `sub.txt`
2. GitHub Actions автоматически запустится каждые 6 часов
3. Результаты появятся в папке `output/`

## Локальный запуск

```bash
pip install -r requirements.txt
python checker.py
