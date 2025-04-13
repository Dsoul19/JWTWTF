import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from core.logic import JWTLogic
from core.engine import JWTEngine
import threading
import os

class JWTWTFGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("JWTWTF - JWT Exploitation Tool v1.3")
        self.root.configure(bg="#1e1e1e")
        self.logic = JWTLogic()
        self.engine = JWTEngine(self.logic)
        self.running = True
        self._apply_theme()
        self._set_icon()  # New method to set the icon
        self._build_gui()

    def _apply_theme(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TFrame", background="#1e1e1e")
        style.configure("TLabel", background="#1e1e1e", foreground="#39ff14", font=("Consolas", 10))
        style.configure("TButton", background="#2e2e2e", foreground="#00ffff", font=("Consolas", 10), borderwidth=1)
        style.map("TButton", background=[("active", "#39ff14"), ("!active", "#2e2e2e")], foreground=[("active", "#1e1e1e")])
        style.configure("TCheckbutton", background="#1e1e1e", foreground="#39ff14", font=("Consolas", 10))
        style.configure("TEntry", fieldbackground="#2e2e2e", foreground="#39ff14", font=("Consolas", 10), insertcolor="white")
        style.configure("TNotebook", background="#1e1e1e", tabfocuscolor="#2e2e2e")
        style.configure("TNotebook.Tab", background="#2e2e2e", foreground="#00ffff", font=("Consolas", 10), padding=[5, 2])
        style.map("TNotebook.Tab", background=[("selected", "#39ff14"), ("active", "#00ffff")], foreground=[("selected", "#1e1e1e")])

    def _set_icon(self):
        # Attempt to load the icon file from the script's directory
        icon_path = os.path.join(os.path.dirname(__file__), "jwtwtf.png")
        try:
            if os.path.exists(icon_path):
                icon = tk.PhotoImage(file=icon_path)
                self.root.iconphoto(True, icon)
            else:
                print(f"[!] Icon file '{icon_path}' not found. Using default window icon.")
        except Exception as e:
            print(f"[!] Error loading icon: {str(e)}. Using default window icon.")

    def _build_gui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Token Input
        ttk.Label(main_frame, text="Enter Token:").grid(row=0, column=0, sticky="w")
        self.token_entry = ttk.Entry(main_frame, width=50)
        self.token_entry.grid(row=0, column=1, columnspan=2, sticky="ew")
        ttk.Button(main_frame, text="Add Token", command=self._add_token).grid(row=0, column=3, padx=5)
        self.token_list = scrolledtext.ScrolledText(main_frame, width=60, height=5, bg="#2e2e2e", fg="#39ff14", insertbackground="white", font=("Consolas", 10))
        self.token_list.grid(row=1, column=0, columnspan=4, pady=5, sticky="ew")

        # Notebook
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=2, column=0, columnspan=5, pady=10, sticky="nsew")

        # Analyze Tab
        analyze_tab = ttk.Frame(notebook)
        notebook.add(analyze_tab, text="Analyze")
        self.analyze_text = scrolledtext.ScrolledText(analyze_tab, width=60, height=20, bg="#2e2e2e", fg="#39ff14", insertbackground="white", font=("Consolas", 10))
        self.analyze_text.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        ttk.Button(analyze_tab, text="Analyze Token", command=self._analyze).pack(pady=5)

        # Attack Tab
        attack_tab = ttk.Frame(notebook)
        notebook.add(attack_tab, text="Attack")
        ttk.Label(attack_tab, text="Select Plugin:").pack(pady=5)
        self.plugin_combo = ttk.Combobox(attack_tab, values=list(self.engine.plugins.keys()), foreground="#39ff14", background="#2e2e2e", font=("Consolas", 10))
        self.plugin_combo.pack(pady=5)
        self.plugin_combo.bind("<<ComboboxSelected>>", self._load_plugin_options)
        self.options_frame = ttk.Frame(attack_tab)
        self.options_frame.pack(pady=5, fill=tk.BOTH)
        self.option_entries = {}
        ttk.Button(attack_tab, text="Run Plugin", command=self._run_plugin).pack(pady=5)
        self.attack_result = scrolledtext.ScrolledText(attack_tab, width=60, height=15, bg="#2e2e2e", fg="#39ff14", insertbackground="white", font=("Consolas", 10))
        self.attack_result.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        # Dynamic Playbook Tab
        playbook_tab = ttk.Frame(notebook)
        notebook.add(playbook_tab, text="Dynamic Playbook")
        self.playbook_list = tk.Listbox(playbook_tab, bg="#2e2e2e", fg="#39ff14", font=("Consolas", 10), height=5, selectmode="multiple")
        for plugin in self.engine.plugins.keys():
            self.playbook_list.insert(tk.END, plugin)
        self.playbook_list.pack(pady=5)
        ttk.Button(playbook_tab, text="Run Playbook", command=self._run_playbook).pack(pady=5)
        self.playbook_log = scrolledtext.ScrolledText(playbook_tab, width=60, height=15, bg="#2e2e2e", fg="#39ff14", insertbackground="white", font=("Consolas", 10))
        self.playbook_log.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        # Extract Tab
        extract_tab = ttk.Frame(notebook)
        notebook.add(extract_tab, text="Extract")
        ttk.Label(extract_tab, text="Target URL:").pack(pady=5)
        self.target_entry = ttk.Entry(extract_tab, width=50)
        self.target_entry.pack(pady=5)
        self.js_var = tk.BooleanVar()
        self.ws_var = tk.BooleanVar()
        self.api_var = tk.BooleanVar()
        self.all_var = tk.BooleanVar()
        ttk.Checkbutton(extract_tab, text="Include JS Files", variable=self.js_var).pack()
        ttk.Checkbutton(extract_tab, text="Include WebSocket", variable=self.ws_var).pack()
        ttk.Checkbutton(extract_tab, text="Include API Endpoints", variable=self.api_var).pack()
        ttk.Checkbutton(extract_tab, text="Return All Tokens", variable=self.all_var).pack()
        ttk.Button(extract_tab, text="Extract Tokens", command=self._extract).pack(pady=10)
        self.extract_result = scrolledtext.ScrolledText(extract_tab, width=60, height=10, bg="#2e2e2e", fg="#39ff14", insertbackground="white", font=("Consolas", 10))
        self.extract_result.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        # Control Buttons
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=3, column=0, columnspan=5, pady=5)
        ttk.Button(control_frame, text="Help", command=self._show_help).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Abort", command=self._abort).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Back", command=self._back).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Exit", command=self._exit).pack(side=tk.RIGHT, padx=5)

        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)

    def _add_token(self):
        token = self.token_entry.get().strip()
        if token:
            tid = f"token_{len(self.logic.tokens)}"
            self.logic.add_token(token, tid)
            self.token_list.insert(tk.END, f"{tid}: {token[:20]}...\n")
            self.token_entry.delete(0, tk.END)
            self.attack_result.insert(tk.END, f"[+] Added token: {tid}\n")
        else:
            messagebox.showwarning("Error", "Please enter a token.", parent=self.root)

    def _load_plugin_options(self, event):
        for widget in self.options_frame.winfo_children():
            widget.destroy()
        plugin_name = self.plugin_combo.get()
        if plugin_name:
            plugin = self.engine.plugins[plugin_name]
            self.engine.use_plugin(plugin_name)
            for opt, details in plugin.options.items():
                ttk.Label(self.options_frame, text=f"{opt} ({'Required' if details['required'] else 'Optional'}):").pack()
                entry = ttk.Entry(self.options_frame, width=40)
                entry.pack()
                if details["default"]:
                    entry.insert(0, details["default"])
                self.option_entries[opt] = entry

    def _analyze(self):
        result = self.logic.analyze()
        self.analyze_text.delete(1.0, tk.END)
        self.analyze_text.insert(tk.END, str(result))

    def _run_plugin(self):
        plugin_name = self.plugin_combo.get()
        if plugin_name:
            self.engine.use_plugin(plugin_name)
            plugin = self.engine.current_plugin
            for opt, entry in self.option_entries.items():
                value = entry.get()
                if value:
                    self.engine.set_plugin_param(opt, value)
            missing = [opt for opt, details in plugin.options.items() if details["required"] and not getattr(plugin, opt, None)]
            if missing:
                self.attack_result.delete(1.0, tk.END)
                self.attack_result.insert(tk.END, f"[!] Missing required options: {', '.join(missing)}\n")
                return
            result = self.engine.run()
            self.attack_result.delete(1.0, tk.END)
            self.attack_result.insert(tk.END, str(result))
        else:
            messagebox.showwarning("Error", "Please select a plugin.", parent=self.root)

    def _run_playbook(self):
        selected = [self.playbook_list.get(i) for i in self.playbook_list.curselection()]
        if not selected:
            messagebox.showwarning("Error", "Select at least one plugin.", parent=self.root)
            return
        self.running = True
        threading.Thread(target=self._execute_playbook, args=(selected,)).start()

    def _execute_playbook(self, plugins):
        self.playbook_log.delete(1.0, tk.END)
        for plugin_name in plugins:
            if not self.running:
                self.playbook_log.insert(tk.END, "[!] Playbook aborted.\n")
                break
            self.engine.use_plugin(plugin_name)
            self.playbook_log.insert(tk.END, f"[*] Running {plugin_name}...\n")
            result = self.engine.run()
            self.playbook_log.insert(tk.END, f"{result}\n")
            self.root.update()

    def _extract(self):
        target = self.target_entry.get()
        if not target:
            messagebox.showwarning("Error", "Please enter a target URL.", parent=self.root)
            return
        self.engine.set_target(target)
        result = self.engine.extract_jwt(
            all=self.all_var.get(),
            js=self.js_var.get(),
            ws=self.ws_var.get(),
            api=self.api_var.get(),
            ws_duration=5
        )
        self.extract_result.delete(1.0, tk.END)
        self.extract_result.insert(tk.END, str(result))

    def _show_help(self):
        help_text = "\n".join([f"{name}: {plugin.description}" for name, plugin in self.engine.plugins.items()])
        messagebox.showinfo("Help", help_text, parent=self.root)

    def _abort(self):
        self.running = False
        self.attack_result.insert(tk.END, "[!] Operation aborted.\n")
        self.playbook_log.insert(tk.END, "[!] Playbook aborted.\n")

    def _back(self):
        self.plugin_combo.set("")
        self.attack_result.delete(1.0, tk.END)
        self.attack_result.insert(tk.END, "[+] Returned to main state.\n")

    def _exit(self):
        self.running = False
        self.root.quit()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    JWTWTFGUI().run()