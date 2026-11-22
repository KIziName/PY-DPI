import ctypes
import functools
from tkinter import messagebox

def is_admin():
    """Проверяет, запущен ли скрипт с правами администратора (Windows API)"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def on_ui(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            self.ui_queue.put_nowait((func, args, kwargs))
        except Exception:
            pass
    return wrapper

def require_admin(title="Ошибка", msg="Нужны права администратора."):
    """Декоратор: проверяет права админа перед выполнением метода"""
    def deco(func):
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            if not is_admin():
                messagebox.showerror(title, msg)
                return None
            return func(self, *args, **kwargs)
        return wrapper
    return deco
