import time
import sys
import ctypes
import socket
import functools
import traceback
import threading
import tkinter as tk
import webbrowser
import queue

from dataclasses import replace
from tkinter import ttk, scrolledtext, messagebox

from config import (
    APP_TITLE, APP_AUTHOR, APP_VERSION, APP_GITHUB,
    TTL_MIN, TTL_MAX,
    MODES, MODES_SPLIT,
    DEFAULT_DOMAINS, DNS_CHECK_DOMAINS, DOCS_SECTIONS, CONFIG, UI, RT,
)

from bypass import DpiBypass, _ip_is_local, pydivert


def is_admin():
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
    def deco(func):
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            if not is_admin():
                messagebox.showerror(title, msg)
                return None
            return func(self, *args, **kwargs)
        return wrapper
    return deco


class App:
    def __init__(self, root):
        self.root = root
        root.title(APP_TITLE)
        root.geometry(UI.window_size)
        root.minsize(*UI.window_min_size)
        root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._controls_enabled = True
        self._test_running = False
        self._test_stop = threading.Event()

        top = ttk.Frame(root, padding=8)
        top.pack(fill=tk.X)

        ttk.Label(top, text="Режим:").pack(side=tk.LEFT)
        self.mode_var = tk.StringVar(value=UI.default_mode)
        self.mode_combo = ttk.Combobox(
            top, textvariable=self.mode_var,
            values=MODES, state="readonly", width=UI.mode_combo_width)
        self.mode_combo.pack(side=tk.LEFT, padx=5)

        ttk.Label(top, text="TTL фейка:").pack(side=tk.LEFT, padx=(10, 0))
        self.ttl_var = tk.StringVar(value=str(CONFIG.fake_ttl))
        self.ttl_entry = ttk.Entry(top, textvariable=self.ttl_var, width=4)
        self.ttl_entry.pack(side=tk.LEFT, padx=5)

        self.start_btn = ttk.Button(top, text="▶ Старт", command=self.toggle)
        self.start_btn.pack(side=tk.RIGHT)

        ttk.Button(top, text="Сбросить лог", command=self.clear_log
                   ).pack(side=tk.RIGHT, padx=5)

        self.test_btn = ttk.Button(top, text="Тест", command=self.test_windivert)
        self.test_btn.pack(side=tk.RIGHT, padx=5)

        ttk.Button(top, text="Документация", command=self.show_docs
                   ).pack(side=tk.RIGHT, padx=5)

        ttk.Button(top, text="О программе", command=self.show_about
                   ).pack(side=tk.RIGHT, padx=5)

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

        mid = ttk.LabelFrame(root, text="Домены", padding=5)
        mid.pack(fill=tk.X, padx=8, pady=5)
        self.domains_text = tk.Text(mid, height=UI.domains_text_height,
                                    wrap="none", state=tk.DISABLED,
                                    bg=UI.domains_bg)
        self.domains_text.pack(fill=tk.X)

        bot = ttk.LabelFrame(root, text="Лог", padding=5)
        bot.pack(fill=tk.BOTH, expand=True, padx=8, pady=5)
        self.log_text = scrolledtext.ScrolledText(
            bot, height=UI.log_text_height, state=tk.DISABLED, font=UI.log_font)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        self.status = tk.StringVar(value="Готов")
        ttk.Label(root, textvariable=self.status, relief=tk.SUNKEN,
                  anchor="w").pack(fill=tk.X, side=tk.BOTTOM)

        self.stats_line = tk.StringVar(value="")
        ttk.Label(root, textvariable=self.stats_line, relief=tk.SUNKEN,
                  anchor="w", font=UI.log_font).pack(fill=tk.X, side=tk.BOTTOM)

        self.log_queue = queue.Queue()
        self.ui_queue = queue.Queue()
        self.bypass = None
        self.thread = None
        self._bypass_gen = 0
        self._watchdog_id = None

        self.mode_var.trace_add("write", lambda *_: self._sync_mode_state())

        self.root.after(UI.log_poll_ms, self._pump_log)
        self.root.after(UI.log_poll_ms, self._pump_ui)
        self.root.after(UI.stats_poll_ms, self._update_stats)

        self.log(f"Python: {sys.version.split()[0]}")
        if is_admin():
            self.log("Админ права: ДА")
        else:
            self.log("Админ права: НЕТ ⚠ — запуск обхода будет недоступен")
        if pydivert is None:
            self.log("⚠ pydivert НЕ УСТАНОВЛЕН. Выполни: pip install pydivert")
        else:
            self.log("pydivert: OK")

        self.fill_domains()
        self._sync_mode_state()

        self.root.after(1000, self._check_dns_async)

    def show_docs(self):
        win = tk.Toplevel(self.root)
        win.title("Документация")
        win.transient(self.root)
        win.geometry("640x560")
        win.minsize(500, 400)

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

        win.update_idletasks()
        px = self.root.winfo_rootx() + (self.root.winfo_width() - win.winfo_width()) // 2
        py = self.root.winfo_rooty() + (self.root.winfo_height() - win.winfo_height()) // 2
        win.geometry(f"+{max(px, 0)}+{max(py, 0)}")

        win.bind("<Escape>", lambda e: win.destroy())

    def _set_controls_enabled(self, enabled):
        self._controls_enabled = enabled
        self.mode_combo.config(state="readonly" if enabled else tk.DISABLED)
        self.test_btn.config(state=tk.NORMAL if enabled else tk.DISABLED)
        self.split_combo.config(state="readonly" if enabled else tk.DISABLED)
        self.bypass_all_chk.config(
            state=tk.NORMAL if enabled else tk.DISABLED)
        self._sync_mode_state()

    def _sync_mode_state(self):
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

    def _on_close(self):
        if self._test_running:
            try:
                self._test_stop.set()
            except Exception:
                pass
            self._test_running = False

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

        while True:
            try:
                self.ui_queue.get_nowait()
            except queue.Empty:
                break

        try:
            self.root.destroy()
        except Exception:
            pass

    def log(self, msg):
        self.log_queue.put(str(msg))

    def clear_log(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state=tk.DISABLED)

    def _pump_log(self):
        try:
            added = False
            while not self.log_queue.empty():
                msg = self.log_queue.get()
                self.log_text.config(state=tk.NORMAL)
                self.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {msg}\n")
                added = True

            if added:
                try:
                    total = int(self.log_text.index("end-1c").split(".")[0]) - 1
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

    def _pump_ui(self):
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

    def _update_stats(self):
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

    @require_admin(title="Тест", msg="Нужны права администратора.")
    def test_windivert(self):
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

                w = pydivert.WinDivert(CONFIG.windivert_test_filter)
                w.open()

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
        self._test_running = False
        if self.thread is None:
            self._set_controls_enabled(True)
            self.start_btn.config(state=tk.NORMAL)

    def _check_dns_async(self):
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

    def toggle(self):
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

        domains = [d.strip() for d in
                   self.domains_text.get("1.0", tk.END).splitlines()
                   if d.strip()]
        if not domains and not bypass_all:
            messagebox.showerror("Ошибка", "Список доменов пуст.")
            return

        mode = self.mode_var.get()

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
        self.stats_line.set("")
        self.start_btn.config(text="▶ Старт", state=tk.NORMAL)
        self.status.set("Остановлено")
        self._set_controls_enabled(True)

    def _stop_bypass(self):
        b = self.bypass
        if b is None:
            return

        self.status.set("Останавливаю…")
        self.start_btn.config(state=tk.DISABLED)

        gen = self._bypass_gen

        def _watchdog():
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

    def fill_domains(self):
        self.domains_text.config(state=tk.NORMAL)
        self.domains_text.delete("1.0", tk.END)
        self.domains_text.insert("1.0", "\n".join(DEFAULT_DOMAINS))
        self.domains_text.config(state=tk.DISABLED)