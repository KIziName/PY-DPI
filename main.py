import sys

# --- Проверка версии Python ---
# Для работы используются конструкции (match/case, dataclass slots), 
# требующие Python 3.10+. Рекомендуется 3.11+.
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
    # --- Проверка прав администратора перед запуском ---
    # Программа использует драйвер WinDivert, который требует повышенных привилегий.
    if not is_admin():
        root = tk.Tk()
        root.withdraw() # Скрываем пустое главное окно
        messagebox.showerror(ADMIN_REQUIRED_TITLE, ADMIN_REQUIRED_MSG)
        root.destroy()
        sys.exit(EXIT_NO_ADMIN)

    # --- Запуск графического интерфейса ---
    root = tk.Tk()
    app = App(root)
    root.mainloop()
