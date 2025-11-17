"""Tkinter-based GUI for the APKraft AI agent workflow."""
from __future__ import annotations

import os
import queue
import shutil
import threading
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Optional

from .agent import APKAgent, OpenRouterClient
from .agent_workflow import (finalize_agent_artifact,
                             prepare_workspace,
                             resolve_agent_output_path)
from .editor import APKEditor


@dataclass
class AgentJobConfig:
    apk: Path
    instructions: str
    api_key: str
    model: str
    temperature: float
    max_steps: int
    output: Optional[Path]
    in_place: bool
    keep_backup: bool
    dry_run: bool
    keep_workspace: bool
    workspace: Optional[Path]
    referer: Optional[str]
    title: Optional[str]
    timeout: float


class AgentGUI(tk.Tk):
    """Simple Tkinter frontend for configuring/running the APK agent."""

    def __init__(self) -> None:
        super().__init__()
        self.title("APKraft Agent")
        self.geometry("900x700")
        self.minsize(800, 600)

        self.apk_var = tk.StringVar()
        self.api_key_var = tk.StringVar(value=os.environ.get("OPENROUTER_API_KEY", ""))
        self.model_var = tk.StringVar(value="kwaipilot/kat-coder-pro:free")
        self.temperature_var = tk.DoubleVar(value=0.2)
        self.max_steps_var = tk.IntVar(value=12)
        self.output_var = tk.StringVar()
        self.workspace_var = tk.StringVar()
        self.in_place_var = tk.BooleanVar(value=False)
        self.keep_backup_var = tk.BooleanVar(value=True)
        self.keep_workspace_var = tk.BooleanVar(value=False)
        self.dry_run_var = tk.BooleanVar(value=False)
        self.timeout_var = tk.DoubleVar(value=90.0)
        self.referer_var = tk.StringVar()
        self.title_var = tk.StringVar()

        self.instructions_text: tk.Text
        self.log_view: scrolledtext.ScrolledText
        self.keep_backup_check: ttk.Checkbutton
        self.keep_workspace_check: ttk.Checkbutton
        self.status_var = tk.StringVar(value="Idle")

        self.log_queue: queue.Queue[str] = queue.Queue()
        self.worker: Optional[threading.Thread] = None

        self._build_layout()
        self._drain_log_queue()

    # ------------------------------------------------------------------
    # UI construction helpers
    # ------------------------------------------------------------------

    def _build_layout(self) -> None:
        container = ttk.Frame(self, padding=10)
        container.grid(row=0, column=0, sticky="nsew")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)

        self._build_apk_row(container)
        self._build_instructions(container)
        self._build_agent_settings(container)
        self._build_output_settings(container)
        self._build_log_view(container)
        self._build_controls(container)

    def _build_apk_row(self, parent: ttk.Frame) -> None:
        frame = ttk.Frame(parent)
        frame.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        frame.columnconfigure(1, weight=1)

        ttk.Label(frame, text="APK file:").grid(row=0, column=0, sticky="w", padx=(0, 6))
        entry = ttk.Entry(frame, textvariable=self.apk_var)
        entry.grid(row=0, column=1, sticky="ew")
        ttk.Button(frame, text="Browse…", command=self._browse_apk).grid(row=0, column=2, padx=(6, 0))

    def _build_instructions(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Agent instructions:").grid(row=1, column=0, sticky="w")
        self.instructions_text = tk.Text(parent, height=5, wrap="word")
        self.instructions_text.grid(row=2, column=0, sticky="nsew", pady=(0, 8))
        parent.rowconfigure(2, weight=1)

    def _build_agent_settings(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="Agent settings", padding=10)
        frame.grid(row=3, column=0, sticky="ew", pady=(0, 8))
        for idx in range(0, 4):
            frame.columnconfigure(idx, weight=1)

        ttk.Label(frame, text="OpenRouter API key:").grid(row=0, column=0, sticky="w")
        api_entry = ttk.Entry(frame, textvariable=self.api_key_var, show="*")
        api_entry.grid(row=1, column=0, columnspan=4, sticky="ew", pady=(0, 8))

        ttk.Label(frame, text="Model:").grid(row=2, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.model_var).grid(row=3, column=0, sticky="ew", padx=(0, 8))

        ttk.Label(frame, text="Temperature:").grid(row=2, column=1, sticky="w")
        ttk.Spinbox(frame,
                    textvariable=self.temperature_var,
                    from_=0.0,
                    to=2.0,
                    increment=0.1,
                    format="%.2f").grid(row=3, column=1, sticky="ew", padx=(0, 8))

        ttk.Label(frame, text="Max steps:").grid(row=2, column=2, sticky="w")
        ttk.Spinbox(frame,
                    textvariable=self.max_steps_var,
                    from_=1,
                    to=40).grid(row=3, column=2, sticky="ew", padx=(0, 8))

        ttk.Label(frame, text="Timeout (s):").grid(row=2, column=3, sticky="w")
        ttk.Spinbox(frame,
                    textvariable=self.timeout_var,
                    from_=10.0,
                    to=300.0,
                    increment=5.0,
                    format="%.1f").grid(row=3, column=3, sticky="ew")

        ttk.Label(frame, text="HTTP Referer (optional):").grid(row=4, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(frame, textvariable=self.referer_var).grid(row=5, column=0, columnspan=2, sticky="ew", padx=(0, 8))

        ttk.Label(frame, text="X-Title (optional):").grid(row=4, column=2, sticky="w", pady=(8, 0))
        ttk.Entry(frame, textvariable=self.title_var).grid(row=5, column=2, columnspan=2, sticky="ew")

    def _build_output_settings(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="Output & workspace", padding=10)
        frame.grid(row=4, column=0, sticky="ew", pady=(0, 8))
        frame.columnconfigure(1, weight=1)

        ttk.Label(frame, text="Output APK (optional):").grid(row=0, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.output_var).grid(row=0, column=1, sticky="ew")
        ttk.Button(frame, text="Browse…", command=self._browse_output).grid(row=0, column=2, padx=(6, 0))

        ttk.Label(frame, text="Workspace directory (optional):").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(frame, textvariable=self.workspace_var).grid(row=1, column=1, sticky="ew", pady=(8, 0))
        ttk.Button(frame, text="Browse…", command=self._browse_workspace).grid(row=1, column=2, padx=(6, 0), pady=(8, 0))

        options = ttk.Frame(frame)
        options.grid(row=2, column=0, columnspan=3, sticky="w", pady=(8, 0))

        ttk.Checkbutton(options,
                        text="Overwrite APK in place",
                        variable=self.in_place_var,
                        command=self._toggle_backup_state).grid(row=0, column=0, sticky="w")
        self.keep_backup_check = ttk.Checkbutton(options,
                                                 text="Keep backup when overwriting",
                                                 variable=self.keep_backup_var)
        self.keep_backup_check.grid(row=0, column=1, sticky="w", padx=(12, 0))
        ttk.Checkbutton(options,
                        text="Dry run (skip rebuild)",
                        variable=self.dry_run_var,
                        command=self._handle_dry_run_toggle).grid(row=1, column=0, sticky="w")
        self.keep_workspace_check = ttk.Checkbutton(options,
                                                    text="Keep workspace after run",
                                                    variable=self.keep_workspace_var)
        self.keep_workspace_check.grid(row=1, column=1, sticky="w", padx=(12, 0))

        self._toggle_backup_state()
        self._handle_dry_run_toggle()

    def _build_log_view(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="Agent output", padding=10)
        frame.grid(row=5, column=0, sticky="nsew", pady=(0, 8))
        parent.rowconfigure(5, weight=2)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.log_view = scrolledtext.ScrolledText(frame, state="disabled", wrap="word")
        self.log_view.grid(row=0, column=0, sticky="nsew")

    def _build_controls(self, parent: ttk.Frame) -> None:
        frame = ttk.Frame(parent)
        frame.grid(row=6, column=0, sticky="ew")
        frame.columnconfigure(0, weight=1)
        ttk.Label(frame, textvariable=self.status_var).grid(row=0, column=0, sticky="w")
        self.run_button = ttk.Button(frame, text="Run agent", command=self.start_agent)
        self.run_button.grid(row=0, column=1, padx=(8, 0))
        ttk.Button(frame, text="Clear log", command=self.clear_log).grid(row=0, column=2, padx=(8, 0))

    # ------------------------------------------------------------------
    # Widget callbacks
    # ------------------------------------------------------------------

    def _browse_apk(self) -> None:
        path = filedialog.askopenfilename(title="Select APK",
                                          filetypes=[("APK files", "*.apk"), ("All files", "*.*")])
        if path:
            self.apk_var.set(path)

    def _browse_output(self) -> None:
        path = filedialog.asksaveasfilename(title="Select output APK",
                                            defaultextension=".apk",
                                            filetypes=[("APK files", "*.apk"), ("All files", "*.*")])
        if path:
            self.output_var.set(path)

    def _browse_workspace(self) -> None:
        path = filedialog.askdirectory(title="Select workspace directory")
        if path:
            self.workspace_var.set(path)

    def _toggle_backup_state(self) -> None:
        if self.in_place_var.get():
            self.keep_backup_check.state(["!disabled"])
        else:
            self.keep_backup_var.set(True)
            self.keep_backup_check.state(["disabled"])

    def _handle_dry_run_toggle(self) -> None:
        if self.dry_run_var.get():
            self.keep_workspace_var.set(True)
            self.keep_workspace_check.state(["disabled"])
        else:
            self.keep_workspace_check.state(["!disabled"])

    # ------------------------------------------------------------------
    # Agent execution helpers
    # ------------------------------------------------------------------

    def start_agent(self) -> None:
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Agent running", "Please wait for the current run to finish.")
            return
        try:
            config = self._collect_config()
        except ValueError as exc:
            messagebox.showerror("Invalid input", str(exc))
            return

        self.status_var.set("Running agent…")
        self._log("Starting agent run…")
        self.run_button.configure(state="disabled")
        self.worker = threading.Thread(target=self._run_agent_thread, args=(config,), daemon=True)
        self.worker.start()

    def _collect_config(self) -> AgentJobConfig:
        apk_raw = self.apk_var.get().strip()
        if not apk_raw:
            raise ValueError("Select an APK file to work on")
        apk_path = Path(apk_raw).expanduser().resolve()
        if not apk_path.exists() or not apk_path.is_file():
            raise ValueError("APK path does not exist or is not a file")

        instructions = self.instructions_text.get("1.0", "end").strip()
        if not instructions:
            raise ValueError("Provide some instructions for the agent")

        api_key = self.api_key_var.get().strip() or os.environ.get("OPENROUTER_API_KEY", "")
        if not api_key:
            raise ValueError("OpenRouter API key is required")

        model = self.model_var.get().strip() or "kwaipilot/kat-coder-pro:free"

        try:
            temperature = float(self.temperature_var.get())
        except (TypeError, ValueError) as exc:
            raise ValueError("Temperature must be a number") from exc
        if not (0.0 <= temperature <= 2.0):
            raise ValueError("Temperature must be between 0.0 and 2.0")

        try:
            max_steps = int(self.max_steps_var.get())
        except (TypeError, ValueError) as exc:
            raise ValueError("Max steps must be an integer") from exc
        if not (1 <= max_steps <= 40):
            raise ValueError("Max steps must be between 1 and 40")

        output_raw = self.output_var.get().strip()
        output_path = Path(output_raw).expanduser().resolve() if output_raw else None

        workspace_raw = self.workspace_var.get().strip()
        workspace_path = Path(workspace_raw).expanduser().resolve() if workspace_raw else None

        in_place = bool(self.in_place_var.get())
        keep_backup = bool(self.keep_backup_var.get()) if in_place else True
        dry_run = bool(self.dry_run_var.get())
        keep_workspace = bool(self.keep_workspace_var.get()) or dry_run

        if in_place and output_path is not None:
            raise ValueError("Cannot specify an output path when overwriting in place")

        try:
            timeout = float(self.timeout_var.get())
        except (TypeError, ValueError) as exc:
            raise ValueError("Timeout must be a number") from exc
        if not (10.0 <= timeout <= 300.0):
            raise ValueError("Timeout must be between 10 and 300 seconds")

        referer = self.referer_var.get().strip() or None
        title = self.title_var.get().strip() or None

        return AgentJobConfig(
            apk=apk_path,
            instructions=instructions,
            api_key=api_key,
            model=model,
            temperature=temperature,
            max_steps=max_steps,
            output=output_path,
            in_place=in_place,
            keep_backup=keep_backup,
            dry_run=dry_run,
            keep_workspace=keep_workspace,
            workspace=workspace_path,
            referer=referer,
            title=title,
            timeout=timeout,
        )

    def _run_agent_thread(self, config: AgentJobConfig) -> None:
        workspace_dir: Optional[Path] = None
        cleanup = False
        final_path: Optional[Path] = None
        success = False
        message = ""

        def log(msg: str) -> None:
            self.log_queue.put(msg)

        try:
            log(f"Loading metadata from {config.apk}…")
            editor = APKEditor(config.apk)
            metadata = editor.metadata()
            try:
                workspace_dir, cleanup = prepare_workspace(config.workspace, config.keep_workspace)
            except ValueError as exc:
                raise RuntimeError(str(exc)) from exc

            log(f"Extracting APK into {workspace_dir}…")
            editor.extract_all(workspace_dir)

            if config.dry_run:
                cleanup = False

            client = OpenRouterClient(api_key=config.api_key,
                                      timeout=config.timeout,
                                      referer=config.referer,
                                      title=config.title)
            agent_runner = APKAgent(workspace=workspace_dir,
                                    metadata=metadata,
                                    client=client,
                                    model=config.model,
                                    instructions=config.instructions,
                                    max_steps=config.max_steps,
                                    temperature=config.temperature)

            result = agent_runner.run()
            log(f"Agent completed in {result.steps} step(s)")
            if result.summary:
                log(result.summary)
            for item in result.changelog:
                log(f"- {item}")

            if config.dry_run:
                log("Dry run enabled: skipping rebuild")
                if workspace_dir:
                    log(f"Workspace preserved at {workspace_dir}")
            else:
                destination = resolve_agent_output_path(config.apk, config.output, config.in_place)
                if not result.modified:
                    log("Agent did not change any files; skipping repack")
                else:
                    log("Repacking modified workspace…")
                    final_path = finalize_agent_artifact(workspace_dir,
                                                         config.apk,
                                                         destination,
                                                         config.in_place,
                                                         config.keep_backup)
                    log(f"Saved updated APK to {final_path}")
                    if config.in_place and config.keep_backup:
                        backup = config.apk.with_name(config.apk.name + ".bak")
                        log(f"Backup stored as {backup}")

            if cleanup and workspace_dir:
                shutil.rmtree(workspace_dir, ignore_errors=True)
                log("Workspace cleaned up")
            elif workspace_dir and not config.dry_run:
                log(f"Workspace left at {workspace_dir}")

            success = True
            message = "Agent run completed"
        except Exception as exc:
            log(f"[ERROR] {exc}")
            message = str(exc)
        finally:
            if workspace_dir and cleanup and not success:
                shutil.rmtree(workspace_dir, ignore_errors=True)
                log("Workspace cleaned up after failure")
            self.after(0, self._on_agent_finished, success, message, final_path)

    def _on_agent_finished(self, success: bool, message: str, final_path: Optional[Path]) -> None:
        self.worker = None
        self.run_button.configure(state="normal")
        self.status_var.set(message)
        if success:
            if final_path:
                messagebox.showinfo("Agent finished", f"Saved updated APK to {final_path}")
            else:
                messagebox.showinfo("Agent finished", message)
        else:
            messagebox.showerror("Agent failed", message)

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------

    def _log(self, message: str) -> None:
        self.log_queue.put(message)

    def clear_log(self) -> None:
        self.log_view.configure(state="normal")
        self.log_view.delete("1.0", tk.END)
        self.log_view.configure(state="disabled")

    def _append_log(self, message: str) -> None:
        self.log_view.configure(state="normal")
        self.log_view.insert(tk.END, message + "\n")
        self.log_view.see(tk.END)
        self.log_view.configure(state="disabled")

    def _drain_log_queue(self) -> None:
        try:
            while True:
                message = self.log_queue.get_nowait()
                self._append_log(message)
        except queue.Empty:
            pass
        self.after(150, self._drain_log_queue)


def launch_agent_gui() -> None:
    """Entry point used by the CLI command."""

    try:
        import tkinter  # noqa: F401 - ensures Tk is available.
    except Exception as exc:  # pragma: no cover - depends on system libs
        raise RuntimeError("Tkinter is not available in this environment") from exc

    app = AgentGUI()
    app.mainloop()
