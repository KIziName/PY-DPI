import sys

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
from dpi import App, is_admin


if __name__ == "__main__":
    if not is_admin():
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(ADMIN_REQUIRED_TITLE, ADMIN_REQUIRED_MSG)
        root.destroy()
        sys.exit(EXIT_NO_ADMIN)

    root = tk.Tk()
    App(root)
    root.mainloop()
