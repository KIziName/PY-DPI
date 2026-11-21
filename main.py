import sys
# Если запустить этот файл на Python 3.9 или ниже, он вылетит с SyntaxError
# при попытке импортировать gui.py (там используется match/case).

if sys.version_info < (3, 10):
    try:
        import tkinter as tk
        from tkinter import messagebox
        
        root = tk.Tk()
        root.withdraw() 
        root.attributes('-topmost', True) 
        
        messagebox.showerror(
            "Ошибка версии Python",
            f"Для работы PY-DPI требуется Python 3.10 или выше.\n\n"
            f"Ваша текущая версия: {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}\n\n"
            f"Пожалуйста, обновите Python до 3.11 или 3.12 с официального сайта python.org."
        )
        root.destroy()
    except Exception:
        # Если вдруг tkinter нет (очень редкий случай), выводим в консоль (если она есть)
        print("КРИТИЧЕСКАЯ ОШИБКА: Требуется Python 3.10 или выше!")
    
    sys.exit(1) # Завершаем работу

# --- Мягкое предупреждение для версий 3.10 (рекомендуем 3.11+) ---
if sys.version_info < (3, 11):
    print(
        f"!! PY-DPI: рекомендуется Python 3.11+ "
        f"(текущая {sys.version_info.major}.{sys.version_info.minor}). "
        f"Продолжаю работу.",
        file=sys.stderr,
    )


import tkinter as tk
from tkinter import messagebox

from config import (
    ADMIN_REQUIRED_TITLE,
    ADMIN_REQUIRED_MSG,
    EXIT_NO_ADMIN,
)
from helpers import is_admin
from gui import App

if __name__ == "__main__":
    if not is_admin():
        root = tk.Tk()
        root.withdraw() 
        root.attributes('-topmost', True) 
        messagebox.showerror(ADMIN_REQUIRED_TITLE, ADMIN_REQUIRED_MSG)
        root.destroy()
        sys.exit(EXIT_NO_ADMIN)

    # --- Запуск графического интерфейса ---
    root = tk.Tk()
    app = App(root)
    root.mainloop()