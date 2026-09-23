import sys
import tkinter as tk

from tkinter import messagebox
from config import APP_TITLE
from dpi import App, is_admin


if __name__ == "__main__":
    if not is_admin():
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            APP_TITLE,
            "Требуются права администратора.\n\n"
            "Запусти PY-DPI от имени администратора:\n"
            "  • ПКМ по ярлыку → «Запуск от имени администратора»\n"
            "  • либо из консоли, открытой с повышенными правами.",
        )
        root.destroy()
        sys.exit(1)

    root = tk.Tk()
    App(root)
    root.mainloop()