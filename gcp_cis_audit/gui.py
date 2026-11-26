"""Tkinter GUI for the CIS GCP audit tool."""
from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import __version__, report
from .demo import DemoClient
from .models import ERROR, FAIL, MANUAL, NA, PASS, Result
from .checks import SECTIONS
from .runner import all_checks, run_audit, select_checks, summarize

_TAG_COLORS = {FAIL: "#fce8e6", ERROR: "#fef7e0", MANUAL: "#f1f3f4", PASS: "#e6f4ea", NA: "#ffffff"}
_SEV_RANK = {"High": 0, "Medium": 1, "Low": 2}


class App(tk.Tk):
    def __init__(self, demo: bool = False):
        super().__init__()
        self.title(f"CIS GCP Audit Tool v{__version__}")
        self.geometry("1280x820")
        self.minsize(1000, 680)

        self.results: list[Result] = []
        self.q: "queue.Queue" = queue.Queue()
        self.stop_evt = threading.Event()
        self.worker: threading.Thread | None = None

        self.auth_mode = tk.StringVar(value="adc")
        self.key_path = tk.StringVar()
        self.token = tk.StringVar()
        self.demo = tk.BooleanVar(value=demo)
        self.level = tk.IntVar(value=2)
        self.section_vars = {s: tk.BooleanVar(value=True) for s in SECTIONS}
        self.status_filter = tk.StringVar(value="All")
        self.status_text = tk.StringVar(value="Ready.")

        self._build()
        self.after(100, self._poll)

    # ------------------------------------------------------------------ UI
    def _build(self):
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Treeview", rowheight=24)

        paned = ttk.PanedWindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=6, pady=6)

        left = ttk.Frame(paned, width=360)
        right = ttk.Frame(paned)
        paned.add(left, weight=0)
        paned.add(right, weight=1)

        # -- authentication
        auth = ttk.LabelFrame(left, text="1. Authentication")
        auth.pack(fill="x", pady=(0, 6))
        ttk.Radiobutton(auth, text="Application Default Credentials (gcloud auth application-default login)",
                        variable=self.auth_mode, value="adc", command=self._auth_changed).pack(anchor="w", padx=6)
        ttk.Radiobutton(auth, text="Service account key file (JSON)", variable=self.auth_mode,
                        value="key", command=self._auth_changed).pack(anchor="w", padx=6)
        row = ttk.Frame(auth)
        row.pack(fill="x", padx=22)
        self.key_entry = ttk.Entry(row, textvariable=self.key_path, state="disabled")
        self.key_entry.pack(side="left", fill="x", expand=True)
        self.key_btn = ttk.Button(row, text="Browse", width=8, state="disabled", command=self._browse_key)
        self.key_btn.pack(side="left", padx=(4, 0))
        ttk.Radiobutton(auth, text="OAuth access token (gcloud auth print-access-token)",
                        variable=self.auth_mode, value="token", command=self._auth_changed).pack(anchor="w", padx=6)
        self.tok_entry = ttk.Entry(auth, textvariable=self.token, show="*", state="disabled")
        self.tok_entry.pack(fill="x", padx=22, pady=(0, 4))
        ttk.Checkbutton(auth, text="Demo mode (offline sample data, no GCP access)", variable=self.demo
                        ).pack(anchor="w", padx=6, pady=(0, 4))

        # -- projects
        proj = ttk.LabelFrame(left, text="2. Projects")
        proj.pack(fill="both", expand=True, pady=(0, 6))
        btns = ttk.Frame(proj)
        btns.pack(fill="x", padx=6, pady=4)
        self.disc_btn = ttk.Button(btns, text="Discover projects", command=self._discover)
        self.disc_btn.pack(side="left")
        ttk.Button(btns, text="Select all", command=lambda: self.proj_list.selection_set(0, "end")
                   ).pack(side="left", padx=4)
        lf = ttk.Frame(proj)
        lf.pack(fill="both", expand=True, padx=6)
        self.proj_list = tk.Listbox(lf, selectmode="extended", exportselection=False, height=7)
        sb = ttk.Scrollbar(lf, command=self.proj_list.yview)
        self.proj_list.configure(yscrollcommand=sb.set)
        self.proj_list.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")
        addf = ttk.Frame(proj)
        addf.pack(fill="x", padx=6, pady=4)
        self.add_var = tk.StringVar()
        e = ttk.Entry(addf, textvariable=self.add_var)
        e.pack(side="left", fill="x", expand=True)
        e.bind("<Return>", lambda _e: self._add_project())
        ttk.Button(addf, text="Add project ID", command=self._add_project).pack(side="left", padx=(4, 0))

        # -- scope
        scope = ttk.LabelFrame(left, text="3. Scope")
        scope.pack(fill="x", pady=(0, 6))
        grid = ttk.Frame(scope)
        grid.pack(fill="x", padx=6)
        for n, s in enumerate(SECTIONS):
            ttk.Checkbutton(grid, text=s, variable=self.section_vars[s]).grid(
                row=n % 5, column=n // 5, sticky="w", padx=(0, 12))
        lv = ttk.Frame(scope)
        lv.pack(fill="x", padx=6, pady=4)
        ttk.Label(lv, text="Profile:").pack(side="left")
        ttk.Radiobutton(lv, text="Level 1 only", variable=self.level, value=1).pack(side="left", padx=6)
        ttk.Radiobutton(lv, text="Level 1 + 2", variable=self.level, value=2).pack(side="left")

        # -- run
        run = ttk.Frame(left)
        run.pack(fill="x")
        self.run_btn = ttk.Button(run, text="Run audit", command=self._start)
        self.run_btn.pack(side="left", fill="x", expand=True)
        self.stop_btn = ttk.Button(run, text="Stop", state="disabled", command=self.stop_evt.set)
        self.stop_btn.pack(side="left", padx=(4, 0))
        self.progress = ttk.Progressbar(left, mode="determinate")
        self.progress.pack(fill="x", pady=4)
        ttk.Label(left, textvariable=self.status_text, wraplength=340, foreground="#5f6368").pack(anchor="w")

        # -- results (right)
        top = ttk.Frame(right)
        top.pack(fill="x")
        self.summary = ttk.Label(top, text="No results yet.", font=("Segoe UI", 10, "bold"))
        self.summary.pack(side="left")
        for txt, fn in (("Export HTML", report.to_html), ("Export CSV", report.to_csv),
                        ("Export JSON", report.to_json)):
            ttk.Button(top, text=txt, command=lambda f=fn, t=txt: self._export(f, t)).pack(side="right", padx=2)
        ttk.Combobox(top, textvariable=self.status_filter, state="readonly", width=9,
                     values=["All", FAIL, ERROR, MANUAL, PASS, NA]).pack(side="right", padx=6)
        ttk.Label(top, text="Show:").pack(side="right")
        self.status_filter.trace_add("write", lambda *_: self._refill())

        cols = ("id", "project", "title", "severity", "status")
        self.tree = ttk.Treeview(right, columns=cols, show="headings", selectmode="browse")
        for c, w in zip(cols, (60, 130, 520, 70, 70)):
            self.tree.heading(c, text=c.title(), command=lambda c=c: self._sort(c))
            self.tree.column(c, width=w, anchor="w", stretch=(c == "title"))
        for st, col in _TAG_COLORS.items():
            self.tree.tag_configure(st, background=col)
        vs = ttk.Scrollbar(right, command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.pack(side="top", fill="both", expand=True, pady=(6, 0))
        vs.place(in_=self.tree, relx=1.0, rely=0, relheight=1.0, anchor="ne")
        self.tree.bind("<<TreeviewSelect>>", self._show_detail)

        self.detail = tk.Text(right, height=11, wrap="word", state="disabled", font=("Segoe UI", 10))
        self.detail.pack(fill="x", pady=(6, 0))
        self.detail.tag_configure("h", font=("Segoe UI", 10, "bold"))

    # --------------------------------------------------------------- helpers
    def _auth_changed(self):
        m = self.auth_mode.get()
        self.key_entry.config(state="normal" if m == "key" else "disabled")
        self.key_btn.config(state="normal" if m == "key" else "disabled")
        self.tok_entry.config(state="normal" if m == "token" else "disabled")

    def _browse_key(self):
        p = filedialog.askopenfilename(title="Service account key", filetypes=[("JSON", "*.json")])
        if p:
            self.key_path.set(p)

    def _add_project(self):
        pid = self.add_var.get().strip()
        if pid and pid not in self.proj_list.get(0, "end"):
            self.proj_list.insert("end", pid)
            self.proj_list.selection_set("end")
        self.add_var.set("")

    def _busy(self, busy: bool):
        self.run_btn.config(state="disabled" if busy else "normal")
        self.disc_btn.config(state="disabled" if busy else "normal")
        self.stop_btn.config(state="normal" if busy else "disabled")

    # ------------------------------------------------------------- discovery
    def _discover(self):
        self._busy(True)
        self.stop_btn.config(state="disabled")
        self.status_text.set("Discovering projects...")

        # Tk variables must be read on the main thread before the worker starts.
        mode, key, tok, demo = self.auth_mode.get(), self.key_path.get(), self.token.get().strip(), self.demo.get()

        def work_safe():
            try:
                if demo:
                    client = DemoClient()
                else:
                    from .client import GcpClient
                    client = GcpClient(mode, key, tok)
                self.q.put(("projects", client.discover_projects()))
            except Exception as exc:
                self.q.put(("error", f"Project discovery failed: {exc}"))
        threading.Thread(target=work_safe, daemon=True).start()

    # ----------------------------------------------------------------- audit
    def _start(self):
        projects = [self.proj_list.get(i) for i in self.proj_list.curselection()]
        if not projects:
            messagebox.showwarning("No projects", "Select (or add) at least one project.")
            return
        secs = [s for s, v in self.section_vars.items() if v.get()]
        checks = select_checks(secs, self.level.get())
        if not checks:
            messagebox.showwarning("No checks", "Select at least one section.")
            return
        mode, key, tok, demo = self.auth_mode.get(), self.key_path.get(), self.token.get().strip(), self.demo.get()
        if not demo and mode == "key" and not key:
            return messagebox.showwarning("Key file", "Choose a service account key file.")
        if not demo and mode == "token" and not tok:
            return messagebox.showwarning("Token", "Paste an access token.")

        self.results = []
        self.tree.delete(*self.tree.get_children())
        self.progress.config(value=0, maximum=len(projects) * len(checks))
        self.stop_evt.clear()
        self._busy(True)
        self.status_text.set("Authenticating...")

        def work():
            try:
                if demo:
                    client = DemoClient()
                else:
                    from .client import GcpClient
                    client = GcpClient(mode, key, tok)
                run_audit(client, projects, checks,
                          on_result=lambda r, d, t: self.q.put(("result", r, d, t)), stop=self.stop_evt)
                self.q.put(("done", self.stop_evt.is_set()))
            except Exception as exc:
                self.q.put(("error", f"Audit failed: {exc}"))
        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()

    def _poll(self):
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "result":
                    _, r, done, total = msg
                    self.results.append(r)
                    self.progress.config(value=done)
                    self.status_text.set(f"[{done}/{total}] {r.project}: {r.check_id}")
                    if self._visible(r):
                        self._insert(r)
                    self._update_summary()
                elif kind == "projects":
                    self.proj_list.delete(0, "end")
                    for p in msg[1]:
                        self.proj_list.insert("end", p)
                    self._busy(False)
                    self.status_text.set(f"Found {len(msg[1])} project(s). Select the ones to audit.")
                elif kind == "done":
                    self._busy(False)
                    self.status_text.set("Stopped." if msg[1] else "Audit complete.")
                elif kind == "error":
                    self._busy(False)
                    self.status_text.set("Error.")
                    messagebox.showerror("Error", msg[1])
        except queue.Empty:
            pass
        self.after(100, self._poll)

    # --------------------------------------------------------------- results
    def _visible(self, r: Result) -> bool:
        f = self.status_filter.get()
        return f == "All" or r.status == f

    def _insert(self, r: Result):
        self.tree.insert("", "end", iid=str(id(r)), tags=(r.status,),
                         values=(r.check_id, r.project, r.title, r.severity, r.status))

    def _refill(self):
        self.tree.delete(*self.tree.get_children())
        for r in self.results:
            if self._visible(r):
                self._insert(r)

    def _sort(self, col):
        def key(item):
            v = self.tree.set(item, col)
            if col == "id":
                return tuple(int(p) for p in v.split("."))
            if col == "severity":
                return _SEV_RANK.get(v, 9)
            return v.lower()
        items = sorted(self.tree.get_children(), key=key)
        for i, it in enumerate(items):
            self.tree.move(it, "", i)

    def _update_summary(self):
        s = summarize(self.results)
        c = s["counts"]
        score = "n/a" if s["score"] is None else f"{s['score']}%"
        self.summary.config(text=f"Score {score}   |   FAIL {c[FAIL]}   ERROR {c[ERROR]}   "
                                 f"MANUAL {c[MANUAL]}   PASS {c[PASS]}   N/A {c[NA]}")

    def _show_detail(self, _evt=None):
        sel = self.tree.selection()
        if not sel:
            return
        r = next((x for x in self.results if str(id(x)) == sel[0]), None)
        if not r:
            return
        t = self.detail
        t.config(state="normal")
        t.delete("1.0", "end")
        t.insert("end", f"{r.check_id}  {r.title}\n", "h")
        t.insert("end", f"Project: {r.project}   Level {r.level}   Severity: {r.severity}   Status: {r.status}\n\n")
        t.insert("end", "Finding: ", "h")
        t.insert("end", f"{r.message}\n")
        if r.resources:
            t.insert("end", "Affected resources:\n", "h")
            for x in r.resources[:50]:
                t.insert("end", f"  - {x}\n")
            if len(r.resources) > 50:
                t.insert("end", f"  ... and {len(r.resources) - 50} more (see export)\n")
        t.insert("end", "\nRationale: ", "h")
        t.insert("end", f"{r.description}\n")
        t.insert("end", "Remediation: ", "h")
        t.insert("end", f"{r.remediation}\n")
        t.config(state="disabled")

    def _export(self, fn, label):
        if not self.results:
            return messagebox.showinfo("Nothing to export", "Run an audit first.")
        ext = {"Export HTML": ".html", "Export CSV": ".csv", "Export JSON": ".json"}[label]
        path = filedialog.asksaveasfilename(defaultextension=ext, initialfile=f"cis-gcp-audit{ext}")
        if path:
            fn(self.results, path)
            self.status_text.set(f"Saved {path}")


def main(demo: bool = False):
    App(demo=demo).mainloop()
