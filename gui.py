import time
import sys
import socket
import traceback
import threading
import re
import tkinter as tk
import webbrowser
import queue
import os
import subprocess
import ssl

from dataclasses import replace
from tkinter import ttk, scrolledtext, messagebox

from config import (
    APP_TITLE, APP_AUTHOR, APP_VERSION, APP_GITHUB,
    TTL_MIN, TTL_MAX,
    MODES, MODES_SPLIT,
    DEFAULT_DOMAINS, DNS_CHECK_DOMAINS, DOCS_SECTIONS, CONFIG, UI, RT,
)

from bypass import DpiBypass, _ip_is_local, pydivert
from helpers import is_admin, on_ui, require_admin

# Точные паттерны для авто-определения уровня лога.
_ERROR_RE = re.compile(r"(❌|\bошибка\b|\berror\b|^!!)", re.IGNORECASE)
_WARN_RE = re.compile(r"(⚠|\bне\s+удалось\b|\bне\s+завершил)", re.IGNORECASE)
_SUCCESS_RE = re.compile(
    r"(\bок\b|\bготов\b|\bзапущен\b|\bда\b|\bзавершён\b)", re.IGNORECASE)


def _guess_level(msg: str):
    """Эвристика для log() без явного level. Возвращает tag или None."""
    if _ERROR_RE.search(msg):
        return "error"
    if _WARN_RE.search(msg):
        return "warning"
    if _SUCCESS_RE.search(msg):
        return "success"
    return None


class App:
    """Главный класс графического интерфейса программы."""
    
    def __init__(self, root):
        """Инициализация окна, виджетов и внутренних переменных."""
        self.root = root
        root.title(APP_TITLE)
        root.geometry(UI.window_size)
        root.minsize(*UI.window_min_size)
        root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._controls_enabled = True
        self._test_running = False
        self._test_stop = threading.Event()

        # ── Верхняя панель ──────────────────────────────────────────────
        top = ttk.Frame(root, padding=8)
        top.pack(fill=tk.X)

        ttk.Label(top, text="Режим:").pack(side=tk.LEFT)
        self.mode_var = tk.StringVar(value=UI.default_mode)
        self.mode_combo = ttk.Combobox(
            top, textvariable=self.mode_var,
            values=MODES, state="readonly", width=UI.mode_combo_width)
        self.mode_combo.pack(side=tk.LEFT, padx=5)

        ttk.Label(top, text="Тема:").pack(side=tk.LEFT, padx=(10, 0))
        self.theme_var = tk.StringVar(value="Светлая")
        self.theme_combo = ttk.Combobox(
            top, textvariable=self.theme_var,
            values=("Светлая", "Темная"), state="readonly", width=8)
        self.theme_combo.pack(side=tk.LEFT, padx=5)
        self.theme_combo.bind("<<ComboboxSelected>>", self._apply_theme)

        ttk.Label(top, text="TTL фейка:").pack(side=tk.LEFT, padx=(10, 0))
        self.ttl_var = tk.StringVar(value=str(CONFIG.fake_ttl))
        self.ttl_entry = ttk.Entry(top, textvariable=self.ttl_var, width=4)
        self.ttl_entry.pack(side=tk.LEFT, padx=5)

        self.start_btn = ttk.Button(top, text="▶ Старт", command=self.toggle)
        self.start_btn.pack(side=tk.RIGHT)

        ttk.Button(top, text="Сбросить лог", command=self.clear_log
                   ).pack(side=tk.RIGHT, padx=5)

        ttk.Button(top, text="Документация", command=self.show_docs
                   ).pack(side=tk.RIGHT, padx=5)


        # ── Панель параметров обхода ───────────────────────────────────
        opts = ttk.Frame(root, padding=(8, 0, 8, 8))
        opts.pack(fill=tk.X)

        ttk.Label(opts, text="Split:").pack(side=tk.LEFT)
        self.split_var = tk.StringVar(value=UI.default_split)
        self.split_combo = ttk.Combobox(
            opts, textvariable=self.split_var,
            values=MODES_SPLIT, state="readonly", width=8)
        self.split_combo.pack(side=tk.LEFT, padx=5)

        ttk.Label(opts, text="Fake-повторы:").pack(side=tk.LEFT, padx=(10, 0))
        self.repeats_var = tk.StringVar(value=str(CONFIG.fake_repeats))
        self.repeats_spin = ttk.Spinbox(
            opts, from_=1, to=5, width=3,
            textvariable=self.repeats_var)
        self.repeats_spin.pack(side=tk.LEFT, padx=5)

        self.badsum_var = tk.BooleanVar(value=CONFIG.fake_badsum)
        self.badsum_chk = ttk.Checkbutton(
            opts, text="битая сумма фейка", variable=self.badsum_var)
        self.badsum_chk.pack(side=tk.LEFT, padx=(10, 0))

        self.bypass_all_var = tk.BooleanVar(value=False)
        self.bypass_all_chk = ttk.Checkbutton(
            opts, text="обход всего",
            variable=self.bypass_all_var,
            command=self._on_bypass_all_toggle)
        self.bypass_all_chk.pack(side=tk.LEFT, padx=(10, 0))

        # ── Домены ─────────────────────────────────────────────────────
        mid = ttk.LabelFrame(root, text="Домены", padding=5)
        mid.pack(fill=tk.X, padx=8, pady=5)
        
        # Создаем один общий фрейм для всех трех кнопок
        btn_row = ttk.Frame(mid)
        btn_row.pack(fill=tk.X, pady=2, padx=2)
        
        # Кнопка управления доменами
        self.dom_btn = ttk.Button(btn_row, text="⚙ Управление списком доменов", 
                                  command=self._open_domains_window)
        self.dom_btn.pack(side=tk.LEFT)

        self.auto_btn = ttk.Button(btn_row, text="⚡Авто-подбор", command=self.run_auto_test)
        self.auto_btn.pack(side=tk.RIGHT,)
       
        self.diag_btn = ttk.Button(btn_row, text="🩺 Диагностика", command=self.run_diagnostics)
        self.diag_btn.pack(side=tk.RIGHT,)

        # Переменная, где будет храниться актуальный список доменов
        self.current_domains = []

        # ── Лог ────────────────────────────────────────────────────────
        bot = ttk.LabelFrame(root, text="Лог", padding=5)
        bot.pack(fill=tk.BOTH, expand=True, padx=8, pady=5)
        self.log_text = scrolledtext.ScrolledText(
            bot, height=UI.log_text_height, state=tk.DISABLED, font=UI.log_font)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Настройка цветов для лога
        self.log_text.tag_config("error", foreground="#e74c3c")   # Красный
        self.log_text.tag_config("warning", foreground="#f39c12") # Оранжевый
        self.log_text.tag_config("success", foreground="#2ecc71") # Зеленый

        self.status = tk.StringVar(value="Готов")
        ttk.Label(root, textvariable=self.status, relief=tk.SUNKEN,
                  anchor="w").pack(fill=tk.X, side=tk.BOTTOM)

        self.stats_line = tk.StringVar(value="")
        ttk.Label(root, textvariable=self.stats_line, relief=tk.SUNKEN,
                  anchor="w", font=UI.log_font).pack(fill=tk.X, side=tk.BOTTOM)

        # Очереди для межпоточного взаимодействия: log_queue — сообщения
        # для лога, ui_queue — вызовы методов в UI-потоке.
        self.log_queue = queue.Queue()
        self.ui_queue = queue.Queue()
        self.bypass = None
        self.thread = None
        # Номер поколения: защищает от «поздних» колбэков завершившегося
        # движка, если пользователь уже нажал Старт снова.
        self._bypass_gen = 0
        self._watchdog_id = None

        self.mode_var.trace_add("write", lambda *_: self._sync_mode_state())

        # Периодические поллеры для UI. Сами перезапускаются в finally.
        self.root.after(UI.log_poll_ms, self._pump_log)
        self.root.after(UI.log_poll_ms, self._pump_ui)
        self.root.after(UI.stats_poll_ms, self._update_stats)

        about_frame = ttk.Frame(root, padding=(8, 0, 8, 8))
        about_frame.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Button(about_frame, text="О программе", command=self.show_about
                   ).pack(side=tk.RIGHT)


        self.log(f"Python: {sys.version.split()[0]}")
      
        self._load_domains()
        self._sync_mode_state()
        self._apply_theme()

    # ── Окна документации / о программе ───────────────────────────────

    def _center_window(self, win):
        """Центрирует дочернее окно относительно главного окна."""
        win.update_idletasks() # Обновляем размеры, чтобы узнать реальную ширину/высоту
        
        # Получаем координаты и размеры главного окна
        root_x = self.root.winfo_rootx()
        root_y = self.root.winfo_rooty()
        root_w = self.root.winfo_width()
        root_h = self.root.winfo_height()
        
        # Получаем размеры дочернего окна
        win_w = win.winfo_width()
        win_h = win.winfo_height()
        
        # Вычисляем позицию для центрирования
        px = root_x + (root_w - win_w) // 2
        py = root_y + (root_h - win_h) // 2
        
        # Применяем координаты (max(0, ...) защищает от вылета за край экрана)
        win.geometry(f"+{max(px, 0)}+{max(py, 0)}")

    def show_docs(self):
        """Открывает окно с документацией (текст берется из config.py)."""
        win = tk.Toplevel(self.root)
        win.title("Документация")
        win.transient(self.root)
        win.geometry("640x560")
        win.minsize(500, 400)
        self._center_window(win)

        frame = ttk.Frame(win, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        txt = scrolledtext.ScrolledText(
            frame, wrap="word", font=("Segoe UI", 9),
            state=tk.NORMAL, bg="#fafafa", relief=tk.FLAT,
            padx=10, pady=8,
        )
        txt.pack(fill=tk.BOTH, expand=True)

        txt.tag_configure("h1", font=("Segoe UI", 13, "bold"),
                          spacing1=10, spacing3=6)
        txt.tag_configure("h2", font=("Segoe UI", 10, "bold"),
                          spacing1=8, spacing3=3)
        txt.tag_configure("p", font=("Segoe UI", 9),
                          lmargin1=8, lmargin2=8, spacing3=2)
        txt.tag_configure("warn", font=("Segoe UI", 9),
                          foreground="#a04000",
                          lmargin1=8, lmargin2=8, spacing3=2)

        for kind, text in DOCS_SECTIONS:
            txt.insert(tk.END, text + "\n", kind)

        txt.config(state=tk.DISABLED)

        btn_row = ttk.Frame(win, padding=(0, 0, 10, 10))
        btn_row.pack(fill=tk.X)
        ttk.Button(btn_row, text="Закрыть", command=win.destroy
                   ).pack(side=tk.RIGHT)

        win.bind("<Escape>", lambda e: win.destroy())

    def show_about(self):
        """Открывает окно 'О программе' с версией и ссылкой на GitHub."""
        win = tk.Toplevel(self.root)
        win.title("О программе")
        win.transient(self.root)
        win.resizable(False, False)
        win.grab_set()

        frame = ttk.Frame(win, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text=f"Версия: {APP_VERSION}"
                  ).pack(anchor="w")

        ttk.Label(frame, text=f"Автор: {APP_AUTHOR}"
                  ).pack(anchor="w")

        link_row = ttk.Frame(frame)
        link_row.pack(anchor="w", pady=(10, 0))
        ttk.Label(link_row, text="GitHub: ").pack(side=tk.LEFT)

        link = tk.Label(
            link_row, text=APP_GITHUB,
            fg=UI.link_fg, cursor="hand2",
            font=UI.about_link_font,
        )
        link.pack(side=tk.LEFT)

        def _open(_event=None):
            try:
                webbrowser.open(APP_GITHUB)
            except Exception as e:
                messagebox.showerror(
                    "Ошибка", f"Не удалось открыть ссылку:\n{e}")

        link.bind("<Button-1>", _open)
        link.bind("<Enter>", lambda e: link.config(fg=UI.link_fg_hover))
        link.bind("<Leave>", lambda e: link.config(fg=UI.link_fg))

        ttk.Separator(frame, orient="horizontal").pack(
            fill=tk.X, pady=12)

        ttk.Button(frame, text="Закрыть", command=win.destroy
                   ).pack(anchor="e")

        self._center_window(win)

        win.bind("<Escape>", lambda e: win.destroy())

    def _get_domains_path(self):
        """Возвращает путь к файлу доменов в папке AppData."""
        appdata = os.environ.get('APPDATA')
        if appdata:
            base_dir = os.path.join(appdata, 'PY-DPI')
        else:
            # Фолбэк, если вдруг AppData нет (маловероятно)
            base_dir = os.path.join(os.path.expanduser('~'), '.config', 'PY-DPI')
            
        os.makedirs(base_dir, exist_ok=True)
        return os.path.join(base_dir, 'domains.txt')

    def _load_domains(self):
        """Загружает домены из AppData. Если файла нет — создает с дефолтными."""
        path = self._get_domains_path()
        if not os.path.exists(path):
            # Если файла нет, сохраняем дефолтные при первом запуске
            self.current_domains = list(DEFAULT_DOMAINS)
            self._save_domains_to_file()
        else:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    lines = [line.strip() for line in f if line.strip()]
                    self.current_domains = lines
            except Exception as e:
                self.log(f"⚠ Ошибка чтения доменов: {e}")
                self.current_domains = list(DEFAULT_DOMAINS)

    def _save_domains_to_file(self):
        """Сохраняет текущий список self.current_domains в файл AppData."""
        path = self._get_domains_path()
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(self.current_domains))
        except Exception as e:
            self.log(f"❌ Ошибка сохранения доменов: {e}")

    def _clean_domain(self, raw_domain):
        """Максимально строгая очистка и валидация домена (только латиница)."""
        if not raw_domain:
            return None
            
        # 1. Убираем все невидимые символы (пробелы, табы, переносы) по краям
        d = raw_domain.strip().lower()
        if not d:
            return None
        
        # 2. Убираем протоколы (http://, https://) и www.
        d = re.sub(r'^https?://', '', d)
        d = re.sub(r'^www\.', '', d)
        
        # 3. Отрезаем пути, порты и якоря (всё, что после /, :, ?)
        d = d.split('/')[0].split(':')[0].split('?')[0].split('#')[0]
        
        # 4. Проверка длины (стандарт DNS - до 253 символов)
        if len(d) > 253 or len(d) < 4:
            return None
            
        # 5. Строгая проверка регуляркой:
        if re.match(r'^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$', d):
            return d
            
        return None

    def _open_domains_window(self):
        """Открывает окно для массового добавления и удаления доменов."""
        win = tk.Toplevel(self.root)
        win.title("Управление доменами")
        win.geometry("550x650")
        self._center_window(win)
        win.transient(self.root)
        win.grab_set()

        frame = ttk.Frame(win, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        # ── 1. Блок текущих доменов ──
        ttk.Label(frame, text="Текущие домены в списке:").pack(anchor="w")
        
        list_frame = ttk.Frame(frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(2, 10))
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, selectmode=tk.EXTENDED, font=("Consolas", 9))
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=listbox.yview)

        for d in sorted(self.current_domains):
            listbox.insert(tk.END, d)

        # ── 2. Блок массового ввода ──
        ttk.Label(frame, text="Вставьте новые домены (каждый с новой строки):").pack(anchor="w")
        
        text_frame = ttk.Frame(frame)
        text_frame.pack(fill=tk.BOTH, expand=True, pady=(2, 5))
        
        text_scroll = ttk.Scrollbar(text_frame)
        text_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Поле ввода: убеждаемся, что state=tk.NORMAL (по умолчанию)
        input_text = tk.Text(text_frame, height=6, font=("Consolas", 9), 
                             yscrollcommand=text_scroll.set, wrap="none")
        input_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        text_scroll.config(command=input_text.yview)

        # --- (ПКМ и горячие клавиши) ---
        def paste_text(event=None):
            try:
                # Получаем текст из буфера обмена Windows
                clipboard_text = win.clipboard_get()
                input_text.insert(tk.INSERT, clipboard_text)
            except tk.TclError:
                pass # Буфер обмена пуст
            
        def select_all(event=None):
            input_text.tag_add(tk.SEL, "1.0", tk.END)
            input_text.mark_set(tk.INSERT, "1.0")
            input_text.see(tk.INSERT)
            return "break"
            
        # Создаем контекстное меню (ПКМ)
        context_menu = tk.Menu(input_text, tearoff=0)
        context_menu.add_command(label="Вставить", command=paste_text)
        context_menu.add_command(label="Выделить всё", command=select_all)

        def show_context_menu(event):
            context_menu.post(event.x_root, event.y_root)

        # Привязываем события
        input_text.bind("<Button-3>", show_context_menu) # ПКМ
        input_text.bind("<Control-v>", paste_text)       # Ctrl+V
        input_text.bind("<Control-V>", paste_text)       # Ctrl+Shift+V 
        input_text.bind("<Control-a>", select_all)       # Ctrl+A
        input_text.bind("<Control-A>", select_all)
        # --------------------------------------------------

        # ── 3. Логика добавления ──
        def add_domains():
            raw_text = input_text.get("1.0", tk.END)
            raw_lines = raw_text.splitlines()
            
            added_count = 0
            skipped_count = 0
            existing = set(listbox.get(0, tk.END))
            
            for line in raw_lines:
                if not line.strip():
                    continue 
                    
                clean = self._clean_domain(line)
                
                if clean:
                    if clean not in existing:
                        listbox.insert(tk.END, clean)
                        existing.add(clean)
                        added_count += 1
                else:
                    skipped_count += 1
            
            input_text.delete("1.0", tk.END)
            
            if added_count > 0 and skipped_count > 0:
                self.log(f"✅ Добавлено: {added_count} | ⚠ Пропущено: {skipped_count}")
            elif added_count > 0:
                self.log(f"✅ Успешно добавлено новых доменов: {added_count}")
            elif skipped_count > 0:
                self.log(f"⚠ Все введенные строки некорректны ({skipped_count} шт.)")
            else:
                self.log("Нет новых доменов для добавления (список пуст).")

        def remove_selected():
            selected = listbox.curselection()
            if not selected:
                return
            for index in reversed(selected):
                listbox.delete(index)

        def save_and_close():
            self.current_domains = list(listbox.get(0, tk.END))
            self._save_domains_to_file()
            win.destroy()
            self.log(f"💾 Список доменов сохранен (всего: {len(self.current_domains)})")

        # ── 4. Кнопки управления ──
        btn_add_frame = ttk.Frame(frame)
        btn_add_frame.pack(fill=tk.X, pady=(0, 10))

        # Переименовали кнопку
        add_btn = ttk.Button(btn_add_frame, text="➕ Добавить в список", command=add_domains)
        add_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        del_btn = ttk.Button(btn_add_frame, text="❌ Удалить выбранные", command=remove_selected)
        del_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
        
        ttk.Separator(frame, orient="horizontal").pack(fill=tk.X, pady=5)

        save_btn = ttk.Button(frame, text="💾 Сохранить и закрыть", command=save_and_close)
        save_btn.pack(fill=tk.X, ipady=5)

    def _apply_theme(self, event=None):
        """Применяет выбранную тему (Светлая/Темная) ко всем виджетам."""
        theme = self.theme_var.get()
        
        # Настраиваем базовую тему (clam лучше всего перекрашивается)
        style = ttk.Style()
        style.theme_use("clam")
        
        if theme == "Темная":
            bg = "#1e1e1e"          # Темный фон
            fg = "#d4d4d4"          # Светлый текст
            field_bg = "#2d2d2d"    # Фон полей ввода
            btn_bg = "#333333"      # Фон кнопок
            border = "#444444"      # Цвет рамок
            
            # Яркие цвета для лога на темном фоне
            log_err = "#ff6b6b"
            log_warn = "#feca57"
            log_ok = "#1dd1a1"
        else:
            bg = "#f0f0f0"
            fg = "#000000"
            field_bg = "#ffffff"
            btn_bg = "#e1e1e1"
            border = "#cccccc"
            
            # Стандартные цвета лога
            log_err = "#e74c3c"
            log_warn = "#f39c12"
            log_ok = "#2ecc71"

        # 1. Настраиваем стили ttk (кнопки, рамки, комбобоксы)
        style.configure(".", background=bg, foreground=fg)
        style.configure("TFrame", background=bg)
        style.configure("TLabelframe", background=bg, bordercolor=border)
        style.configure("TLabelframe.Label", background=bg, foreground=fg)
        style.configure("TLabel", background=bg, foreground=fg)
        
        style.configure("TButton", background=btn_bg, foreground=fg, bordercolor=border)
        style.map("TButton", background=[("active", border)])
        
        style.configure("TEntry", fieldbackground=field_bg, foreground=fg, bordercolor=border)
        style.configure("TCombobox", fieldbackground=field_bg, foreground=fg, bordercolor=border)
        style.configure("TSpinbox", fieldbackground=field_bg, foreground=fg, bordercolor=border)
        
        style.configure("TCheckbutton", background=bg, foreground=fg)
        style.map("TCheckbutton", background=[("active", bg)])

        # 2. Красим главное окно и статус-бар
        self.root.configure(bg=bg)

        # 3. Красим текстовое поле лога (и курсор)
        self.log_text.configure(bg=field_bg, fg=fg, insertbackground=fg)

        # 4. Обновляем цвета тегов в логе
        self.log_text.tag_config("error", foreground=log_err)
        self.log_text.tag_config("warning", foreground=log_warn)
        self.log_text.tag_config("success", foreground=log_ok)

    # ── Блокировка контролов ──────────────────────────────────────────

    def _set_controls_enabled(self, enabled):
        """Включает или выключает элементы управления (во время работы)."""
        self._controls_enabled = enabled
        self.mode_combo.config(state="readonly" if enabled else tk.DISABLED)
        self.dom_btn.config(state=tk.NORMAL if enabled else tk.DISABLED)
        self.auto_btn.config(state=tk.NORMAL if enabled else tk.DISABLED) 
        self.split_combo.config(state="readonly" if enabled else tk.DISABLED)
        self.bypass_all_chk.config(state=tk.NORMAL if enabled else tk.DISABLED)
        self.dom_btn.config(state=tk.NORMAL if enabled else tk.DISABLED)
        self._sync_mode_state()

        self.diag_btn.config(state=tk.NORMAL if enabled else tk.DISABLED)

    def _sync_mode_state(self):
        """Блокирует поля TTL/повторов/badsum, если выбран режим без fake."""
        if not self._controls_enabled:
            self.ttl_entry.config(state=tk.DISABLED)
            self.badsum_chk.config(state=tk.DISABLED)
            self.repeats_spin.config(state=tk.DISABLED)
            self.bypass_all_chk.config(state=tk.DISABLED)
            return

        mode = self.mode_var.get()
        fake = mode.startswith("fake")

        self.ttl_entry.config(state=tk.NORMAL if fake else tk.DISABLED)
        self.badsum_chk.config(state=tk.NORMAL if fake else tk.DISABLED)
        self.repeats_spin.config(state=tk.NORMAL if fake else tk.DISABLED)
        self.bypass_all_chk.config(state=tk.NORMAL)

    def _on_bypass_all_toggle(self):
        """Показывает предупреждение при включении 'Обхода всего'."""
        if not self.bypass_all_var.get():
            return
        ok = messagebox.askyesno(
            "Обход всего",
            "ВНИМАНИЕ!\n\n"
            "В этом режиме PY-DPI будет обходить любое соединение, "
            "а не только домены из списка.\n\n"
            "Это может:\n"
            "  • ломать соединения отдельных сайтов\n"
            "  • вызывать проблемы с приложениями\n"
            "  • замедлять трафик\n\n"
            "Включить обход всего?"
        )
        if not ok:
            self.bypass_all_var.set(False)

    # ── Закрытие окна ─────────────────────────────────────────────────

    def _on_close(self):
        """Корректное завершение работы: остановка потоков, очистка, выход."""
        if self._test_running:
            try:
                self._test_stop.set()
            except Exception:
                pass
            self._test_running = False

        # Отменяем watchdog, если он ещё висит — прибираемся до destroy().
        if self._watchdog_id is not None:
            try:
                self.root.after_cancel(self._watchdog_id)
            except tk.TclError:
                pass
            self._watchdog_id = None

        b = self.bypass
        t = self.thread

        if b is not None:
            try:
                b.stop()
            except Exception:
                pass

        if (t is not None and t.is_alive()
                and t is not threading.current_thread()):
            t.join(timeout=RT.close_join_timeout_s)

        # Чистим накопившиеся UI-вызовы — они уже никому не нужны.
        while True:
            try:
                self.ui_queue.get_nowait()
            except queue.Empty:
                break

        try:
            self.root.destroy()
        except Exception:
            pass

    # ── Лог ───────────────────────────────────────────────────────────

    def log(self, msg, level=None):

        self.log_queue.put((str(msg), level))

    def clear_log(self):
        """Очищает окно лога."""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state=tk.DISABLED)

    def _pump_log(self):
        """Переносит сообщения из очереди в UI-виджет (вызывается периодически)."""
        try:
            batch = []
            while True:
                try:
                    batch.append(self.log_queue.get_nowait())
                except queue.Empty:
                    break

            if batch:
                self.log_text.config(state=tk.NORMAL)
                try:
                    for item in batch:
                        # Совместимость: если кто-то положил в очередь голую строку.
                        if isinstance(item, tuple):
                            msg, level = item
                        else:
                            msg, level = item, None
                        tag = level if level is not None else _guess_level(msg)
                        self.log_text.insert(
                            tk.END,
                            f"[{time.strftime('%H:%M:%S')}] {msg}\n", tag)

                    total = int(
                        self.log_text.index("end-1c").split(".")[0]) - 1
                    if total > UI.max_log_lines:
                        self.log_text.delete(
                            "1.0", f"{total - UI.max_log_lines + 1}.0")
                    self.log_text.see(tk.END)
                finally:
                    self.log_text.config(state=tk.DISABLED)
        finally:
            try:
                self.root.after(UI.log_poll_ms, self._pump_log)
            except tk.TclError:
                pass

    # ── UI-очередь ────────────────────────────────────────────────────

    def _pump_ui(self):
        """Выполняет отложенные UI-колбэки (из других потоков)."""
        try:
            while True:
                try:
                    func, args, kwargs = self.ui_queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    func(self, *args, **kwargs)
                except Exception:
                    pass
        finally:
            try:
                self.root.after(UI.log_poll_ms, self._pump_ui)
            except tk.TclError:
                pass

    # ── Строка статистики ─────────────────────────────────────────────

    def _update_stats(self):
        """Обновляет нижнюю строку со статистикой скорости и пакетов."""
        try:
            b = self.bypass
            if b is not None and b.running:
                s = b.get_stats()

                total = s["bytes"]
                if total >= 1024 * 1024:
                    total_str = f"{total / 1024 / 1024:.1f} МБ"
                elif total >= 1024:
                    total_str = f"{total / 1024:.1f} КБ"
                else:
                    total_str = f"{total} Б"

                bw = s["bw_bps"]
                if bw >= 1024 * 1024:
                    bw_str = f"{bw / 1024 / 1024:.1f} МБ/с"
                elif bw >= 1024:
                    bw_str = f"{bw / 1024:.1f} КБ/с"
                else:
                    bw_str = f"{bw:.0f} Б/с"

                self.stats_line.set(
                    f"обойдено: {s['bypassed']:,} пак. / {total_str} | "
                    f"{bw_str} | "
                    f"QUIC: {s['quic_dropped']:,} | "
                    f"pending: {s['pending_pkts']}/{s['pending_conn']} пак/соед"
                )
            else:
                self.stats_line.set("")
        finally:
            try:
                self.root.after(UI.stats_poll_ms, self._update_stats)
            except tk.TclError:
                pass

    # ── Тест WinDivert ────────────────────────────────────────────────

    @require_admin(title="Тест", msg="Нужны права администратора.")
    def test_windivert(self):
        """Запускает тест драйвера WinDivert (пересылка пакетов)."""
        if pydivert is None:
            messagebox.showerror("Тест", "pip install pydivert")
            return

        if self.thread is not None:
            messagebox.showinfo("Тест", "Сначала останови обход.")
            return

        if self._test_running:
            return

        self._test_running = True
        self._test_stop = threading.Event()
        self._set_controls_enabled(False)
        self.start_btn.config(state=tk.DISABLED)

        def worker():
            self.log("— ТЕСТ: открываю WinDivert —")
            w = None
            stop_ev = self._test_stop
            recv_q = queue.Queue(maxsize=RT.packet_queue_maxsize)
            n = 0
            rt = None
            try:
                if stop_ev.is_set():
                    return

                try:
                    w = pydivert.WinDivert(CONFIG.windivert_test_filter)
                    w.open()
                except Exception as e:
                    self.log(f"!! не удалось открыть WinDivert: {e}")
                    return

                if stop_ev.is_set():
                    return

                local_w = w

                self.log(
                    f"WinDivert открыт. Считаю {CONFIG.test_duration_s} сек…")

                def receiver():
                    while not stop_ev.is_set():
                        try:
                            p = local_w.recv()
                        except Exception:
                            return
                        try:
                            recv_q.put(p, timeout=RT.queue_put_timeout_s)
                        except queue.Full:
                            try:
                                local_w.send(p)
                            except Exception:
                                return

                rt = threading.Thread(target=receiver, daemon=True)
                rt.start()

                t0 = time.time()
                send_error = False
                while time.time() - t0 < CONFIG.test_duration_s:
                    if stop_ev.is_set():
                        break
                    try:
                        p = recv_q.get(timeout=RT.queue_get_timeout_s)
                    except queue.Empty:
                        continue
                    try:
                        local_w.send(p)
                        n += 1
                    except Exception as e:
                        self.log(f"send err: {e}")
                        send_error = True
                        break

                aborted = stop_ev.is_set()

                stop_ev.set()

                # Дренаж очереди — вернуть всё, что успело прийти.
                while True:
                    try:
                        p = recv_q.get_nowait()
                    except queue.Empty:
                        break
                    try:
                        local_w.send(p)
                        n += 1
                    except Exception:
                        pass

                try:
                    local_w.close()
                except Exception:
                    pass
                w = None

                if rt is not None and rt.is_alive():
                    rt.join(timeout=RT.recv_join_timeout_s)

                if aborted:
                    self.log(f"— ТЕСТ прерван: переслано {n} пакетов —")
                elif send_error:
                    self.log(f"— ТЕСТ прерван ошибкой отправки: "
                             f"переслано {n} пакетов —")
                else:
                    self.log(f"— ТЕСТ завершён: переслано {n} пакетов —")
            except Exception:
                for line in traceback.format_exc().splitlines():
                    self.log("  " + line)
            finally:
                stop_ev.set()
                if w is not None:
                    try:
                        w.close()
                    except Exception:
                        pass
                self._on_test_done()

        threading.Thread(target=worker, daemon=True).start()

    @on_ui
    def _on_test_done(self):
        """Вызывается после завершения теста (возвращает кнопки в строй)."""
        self._test_running = False
        if self.thread is None:
            self._set_controls_enabled(True)
            self.start_btn.config(state=tk.NORMAL)

    # ── Проверка DNS на подмену ───────────────────────────────────────

    def _check_dns_async(self):
        """Фоновая проверка популярных доменов на подмену DNS (локальные IP)."""
        def worker():
            sample = DNS_CHECK_DOMAINS
            bad = []
            resolved = 0
            for d in sample:
                try:
                    ip = socket.gethostbyname(d)
                    resolved += 1
                except Exception:
                    continue
                try:
                    if _ip_is_local(ip, True):
                        bad.append((d, ip))
                except Exception:
                    continue

            for d, ip in bad:
                self.log(f"⚠ {d} → {ip} — похоже на подмену DNS")

            if bad:
                self.log(f"⚠ Найдено {len(bad)} из {resolved} популярных "
                         f"доменов с локальными IP — "
                         f"проверь DNS-сервер (8.8.8.8 / 1.1.1.1)")
            elif resolved == 0:
                self.log("DNS-проверка: не удалось разрешить ни один домен "
                         "(нет интернета или DNS недоступен)")
            else:
                self.log(f"DNS-проверка: {resolved} из {len(sample)} "
                         f"популярных доменов — ОК")

        threading.Thread(target=worker, daemon=True,
                         name="dns-check").start()

    # ── Старт / стоп обхода ───────────────────────────────────────────

    def toggle(self):
        """Обработчик кнопки Старт/Стоп (запуск и остановка движка)."""
        if self.thread is not None:
            self._stop_bypass()
            return

        if not is_admin():
            messagebox.showerror(
                "Ошибка",
                "Нужны права администратора.\n\n"
                "Запусти PY-DPI от имени администратора "
                "(ПКМ по ярлыку → «Запуск от имени администратора»).",
            )
            return

        if self._test_running:
            messagebox.showinfo("Старт", "Дождись окончания теста.")
            return

        if pydivert is None:
            messagebox.showerror("Ошибка", "pip install pydivert")
            return

        bypass_all = bool(self.bypass_all_var.get())

        # БЕРЕМ ДОМЕНЫ ИЗ НАШЕГО НОВОГО СПИСКА 
        domains = self.current_domains
        
        if not domains and not bypass_all:
            messagebox.showerror("Ошибка", "Список доменов пуст. Добавь домены или включи 'обход всего'.")
            return

        mode = self.mode_var.get()

        # Валидация числовых полей; вне fake-режимов — мягкий фолбэк.
        try:
            ttl = int(self.ttl_var.get())
            if not TTL_MIN <= ttl <= TTL_MAX:
                raise ValueError
        except ValueError:
            if mode.startswith("fake"):
                messagebox.showerror(
                    "Ошибка", f"TTL должен быть числом {TTL_MIN}..{TTL_MAX}")
                return
            ttl = CONFIG.fake_ttl

        split_pos = self.split_var.get()
        if split_pos not in MODES_SPLIT:
            split_pos = CONFIG.split_pos

        try:
            repeats = int(self.repeats_var.get())
            if not 1 <= repeats <= 5:
                raise ValueError
        except ValueError:
            if mode.startswith("fake"):
                messagebox.showerror(
                    "Ошибка", "Fake-повторов должно быть 1..5")
                return
            repeats = CONFIG.fake_repeats

        cfg = replace(
            CONFIG,
            fake_ttl=ttl,
            fake_badsum=bool(self.badsum_var.get()),
            split_pos=split_pos,
            fake_repeats=repeats,
        )

        self.status.set("Запускаю…")
        self.start_btn.config(text="■ Стоп")

        # Новое поколение: колбэк старого движка (если он ещё не отстрелил)
        # не должен влиять на новый UI.
        self._bypass_gen += 1
        gen = self._bypass_gen

        self.bypass = DpiBypass(
            domains=domains,
            mode=mode,
            log_cb=self.log,
            done_cb=lambda g=gen: self._on_bypass_done(g),
            config=cfg,
            bypass_all=bypass_all,
        )

        self.thread = threading.Thread(target=self.bypass.run, daemon=True)
        self.thread.start()

        self._set_controls_enabled(False)
        if bypass_all:
            self.log("⚠ РЕЖИМ: обход всего включён")
            self.status.set(f"Работаю — режим {mode} (обход всего)")
        else:
            self.status.set(f"Работаю — режим {mode}")

    def _reset_ui(self):
        """Сбрасывает интерфейс в исходное состояние (после остановки)."""
        self.stats_line.set("")
        self.start_btn.config(text="▶ Старт", state=tk.NORMAL)
        self.status.set("Остановлено")
        self._set_controls_enabled(True)

    def _stop_bypass(self):
        """Инициирует остановку движка с защитным таймером (watchdog)."""
        b = self.bypass
        if b is None:
            return

        self.status.set("Останавливаю…")
        self.start_btn.config(state=tk.DISABLED)

        gen = self._bypass_gen

        def _watchdog():
            # Если поток не завершился штатно за RT.stop_watchdog_ms —
            # принудительно отпускаем UI, чтобы окно не «залипло».
            self._watchdog_id = None
            if self._bypass_gen != gen:
                return
            if self.thread is None:
                return
            self.log("⚠ Поток не завершился штатно за "
                     f"{RT.stop_watchdog_ms // 1000} с — принудительный сброс UI")
            self.bypass = None
            self.thread = None
            self._bypass_gen += 1
            self._reset_ui()

        if self._watchdog_id is not None:
            try:
                self.root.after_cancel(self._watchdog_id)
            except tk.TclError:
                pass
            self._watchdog_id = None

        try:
            self._watchdog_id = self.root.after(
                RT.stop_watchdog_ms, _watchdog)
        except tk.TclError:
            self._watchdog_id = None

        try:
            b.stop()
        except Exception:
            pass

    @on_ui
    def _on_bypass_done(self, gen):
        """Колбэк от движка: вызывается, когда поток обхода полностью завершен."""
        # Игнорируем колбэк устаревшего поколения движка.
        if gen != self._bypass_gen:
            return
        if self._watchdog_id is not None:
            try:
                self.root.after_cancel(self._watchdog_id)
            except tk.TclError:
                pass
            self._watchdog_id = None
        self.bypass = None
        self.thread = None
        self._reset_ui()

    def run_diagnostics(self):
        """Запускает окно диагностики с проверкой WinDivert и DNS."""
        win = tk.Toplevel(self.root)
        win.title("Диагностика PY-DPI")
        win.geometry("550x450")
        self._center_window(win)
        win.transient(self.root)
        win.grab_set()

        # Флаг закрытия окна
        state = {"is_closed": False}

        def on_close():
            state["is_closed"] = True
            win.destroy()

        win.protocol("WM_DELETE_WINDOW", on_close)

        bg_color = self.root.cget("bg")
        win.configure(bg=bg_color)

        frame = ttk.Frame(win, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        txt = scrolledtext.ScrolledText(frame, wrap=tk.WORD, font=UI.log_font, state=tk.DISABLED)
        txt.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        txt.tag_config("ok", foreground="#2ecc71")
        txt.tag_config("err", foreground="#e74c3c")
        txt.tag_config("warn", foreground="#f39c12")
        txt.tag_config("info", foreground="#3498db")

        # Безопасная запись в лог
        def _log(msg, tag=None):
            if state["is_closed"]:
                return
            try:
                win.after(0, lambda: _insert_log(msg, tag))
            except tk.TclError:
                pass
            
        def _insert_log(msg, tag):
            if state["is_closed"]:
                return
            try:
                txt.config(state=tk.NORMAL)
                if tag:
                    txt.insert(tk.END, msg + "\n", tag)
                else:
                    txt.insert(tk.END, msg + "\n")
                txt.see(tk.END)
                txt.config(state=tk.DISABLED)
            except tk.TclError:
                pass

        # Создаем кнопку закрытия 
        btn_close = ttk.Button(frame, text="Пожалуйста, подождите...", state=tk.DISABLED)
        btn_close.pack()

        def _finish_test():
            """Разблокирует кнопку закрытия."""
            if state["is_closed"]:
                return
            btn_close.config(state=tk.NORMAL, text="Закрыть", command=on_close)

        def worker():
            _log("=== Запуск диагностики ===", "info")
            
            # Шаг 1: Права
            _log("Шаг 1: Проверка прав администратора...")
            if state["is_closed"]: return
            if is_admin():
                _log("✅ Права администратора: ДА", "ok")
            else:
                _log("❌ Права администратора: НЕТ", "err")
                _log("   Запустите программу от имени администратора!", "warn")
                win.after(0, _finish_test)
                return

            # Шаг 2: pydivert
            _log("\nШаг 2: Проверка библиотеки pydivert...")
            if state["is_closed"]: return
            if pydivert is None:
                _log("❌ pydivert НЕ УСТАНОВЛЕН", "err")
                _log("   Выполните: pip install pydivert", "warn")
                win.after(0, _finish_test)
                return
            else:
                _log("✅ pydivert: OK", "ok")

            # Шаг 3: DNS
            _log("\nШаг 3: Проверка подмены DNS...")
            if state["is_closed"]: return
            bad_dns = []
            sample = DNS_CHECK_DOMAINS
            resolved = 0
            for d in sample:
                if state["is_closed"]: return
                try:
                    ip = socket.gethostbyname(d)
                    resolved += 1
                    if _ip_is_local(ip, True):
                        bad_dns.append((d, ip))
                except Exception:
                    pass
            
            if bad_dns:
                for d, ip in bad_dns:
                    _log(f"⚠ {d} -> {ip} (похоже на подмену DNS)", "warn")
                _log("⚠ Смените DNS на 8.8.8.8 или 1.1.1.1", "warn")
            elif resolved == 0:
                _log("⚠ Не удалось разрешить ни один домен (проверьте интернет)", "warn")
            else:
                _log(f"✅ DNS работает нормально ({resolved}/{len(sample)})", "ok")

            _log("\nШаг 3.5: Проверка брандмауэра Windows...")
            if state["is_closed"]: return
            try:
                # Вызываем системную утилиту netsh и читаем ответ
                res = subprocess.run(
                    ['netsh', 'advfirewall', 'show', 'allprofiles'],
                    capture_output=True, text=True, encoding='cp866', errors='ignore',
                    creationflags=subprocess.CREATE_NO_WINDOW 
                )    

                out = res.stdout.upper()
                
                # Проверяем, есть ли в ответе "ON" (англ) или "ВКЛ" (рус)
                if "ON" in out or "ВКЛ" in out:
                    _log("⚠ Брандмауэр Windows включен.", "warn")
                    _log("   Если обход не работает, разрешите Python и PY-DPI в брандмауэре.", "info")
                else:
                    _log("✅ Брандмауэр Windows выключен (или не блокирует).", "ok")
            except Exception as e:
                _log(f"ℹ Не удалось проверить брандмауэр: {e}", "info")

            # Шаг 4: WinDivert
            _log(f"\nШаг 4: Тест драйвера WinDivert ({CONFIG.test_duration_s} сек)...")
            if state["is_closed"]: return
            
            stop_ev = threading.Event()
            
            def check_closed():
                if state["is_closed"]:
                    stop_ev.set()
                else:
                    try: win.after(100, check_closed)
                    except tk.TclError: pass
            
            win.after(100, check_closed)

            w = None
            recv_q = queue.Queue(maxsize=RT.packet_queue_maxsize)
            n = 0
            
            try:
                w = pydivert.WinDivert(CONFIG.windivert_test_filter)
                w.open()
            except Exception as e:
                _log(f"❌ Ошибка открытия WinDivert: {e}", "err")
                win.after(0, _finish_test)
                return
            
            _log("Драйвер открыт. Пересылаю пакеты...", "info")
            
            def receiver():
                while not stop_ev.is_set():
                    try:
                        p = w.recv()
                    except Exception:
                        return
                    try:
                        recv_q.put(p, timeout=0.3)
                    except queue.Full:
                        try: w.send(p)
                        except: return

            rt = threading.Thread(target=receiver, daemon=True)
            rt.start()

            t0 = time.time()
            while time.time() - t0 < CONFIG.test_duration_s and not stop_ev.is_set():
                try:
                    p = recv_q.get(timeout=0.2)
                    w.send(p)
                    n += 1
                except queue.Empty:
                    continue
                except Exception:
                    pass

            stop_ev.set()
            
            # Дренаж
            while True:
                try:
                    p = recv_q.get_nowait()
                    w.send(p)
                    n += 1
                except queue.Empty:
                    break
                except Exception:
                    pass
            
            try: w.close()
            except: pass
            
            if not state["is_closed"]:
                if n > 0:
                    _log(f"✅ Тест пройден: успешно переслано {n} пакетов", "ok")
                else:
                    _log("⚠ Тест завершен, но переслано 0 пакетов. Нет трафика?", "warn")
                _log("\n=== Диагностика завершена ===", "info")
                
                # Разблокируем кнопку
                win.after(0, _finish_test)

        # Запускаем поток
        threading.Thread(target=worker, daemon=True).start()

    def run_auto_test(self):
        """Перебирает режимы на лету и выбирает самый быстрый."""
        if self.thread is not None:
            messagebox.showinfo("Авто-тест", "Сначала остановите обход.")
            return
            
        if not is_admin():
            messagebox.showerror("Ошибка", "Нужны права администратора.")
            return

        self.auto_btn.config(state=tk.DISABLED)
        self.start_btn.config(state=tk.DISABLED)
        self.status.set("⚡ Идет авто-подбор режима...")
        self.log("=== Начат авто-подбор режима ===", "info")
        self.log("⚠ Не используйте браузер во время теста (займет ~10-15 сек)", "warning")

        def worker():
            modes_to_test = ["split", "disorder", "triple_disorder", "triple_split", "fake+split", "fake+disorder"]
            results = {}
            target_host = "youtube.com"
            test_domains = ["youtube.com", "googlevideo.com"]

            start_mode = modes_to_test[0]
            cfg = replace(CONFIG, split_pos=self.split_var.get())
            engine = DpiBypass(
                domains=test_domains, 
                mode=start_mode, 
                log_cb=lambda x: None,
                config=cfg
            )
            
            t = threading.Thread(target=engine.run, daemon=True)
            t.start()
            
            time.sleep(2.0) # Ждем инициализации драйвера
            
            try:
                for mode in modes_to_test:
                    self.log(f"Тестирую режим: {mode}...")
                    
                    engine.mode = mode # МЕНЯЕМ РЕЖИМ НА ЛЕТУ
                    time.sleep(0.5)
                    
                    success = False
                    elapsed = 99.0
                    
                    try:
                        t0 = time.time()
                        context = ssl.create_default_context()
                        with socket.create_connection((target_host, 443), timeout=4) as sock:
                            with context.wrap_socket(sock, server_hostname=target_host):
                                success = True
                                elapsed = time.time() - t0
                    except Exception:
                        success = False
                    
                    if success:
                        self.log(f"✅ {mode} работает! ({elapsed:.2f} сек)", "success")
                        results[mode] = elapsed
                    else:
                        self.log(f"❌ {mode} не сработал.", "error")
            finally:
                engine.stop()
                t.join(timeout=2)

            # Выбор победителя
            if not results:
                self.log("⚠ Ни один режим не смог подключиться.", "warning")
                msg = "Не удалось подобрать режим.\nВозможно, нет интернета или включен VPN."
                self.root.after(0, lambda: messagebox.showerror("Авто-тест", msg))
            else:
                best_mode = min(results, key=results.get)
                best_time = results[best_mode]
                
                self.log(f"🏆 Лучший режим: {best_mode} ({best_time:.2f} сек)", "success")
                
                def apply_best():
                    self.mode_var.set(best_mode)
                    self._sync_mode_state()
                    messagebox.showinfo("Авто-тест", 
                        f"Успешно!\nВыбран режим: {best_mode}\nВремя: {best_time:.2f} сек.")
                
                self.root.after(0, apply_best)

            def reset_buttons():
                self.auto_btn.config(state=tk.NORMAL)
                self.start_btn.config(state=tk.NORMAL)
                self.status.set("Готов")
            self.root.after(0, reset_buttons)

        threading.Thread(target=worker, daemon=True).start()
