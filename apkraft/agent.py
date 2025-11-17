"""LLM-backed agent helpers for APKraft."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import json
import shutil
import textwrap

import httpx
from rich.console import Console

from .editor import APKMetadata


@dataclass(frozen=True)
class AgentRunResult:
    """Summary of an agent session."""

    steps: int
    summary: str
    changelog: List[str]
    modified: bool


class OpenRouterClient:
    """Thin wrapper around the OpenRouter chat completions API."""

    def __init__(self,
                 api_key: str,
                 *,
                 base_url: str = "https://openrouter.ai/api/v1",
                 timeout: float = 60.0,
                 referer: Optional[str] = None,
                 title: Optional[str] = None) -> None:
        if not api_key:
            raise ValueError("OpenRouter API key is required")
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.referer = referer
        self.title = title

    def chat(self,
             *,
             messages: List[Dict[str, str]],
             model: str,
             temperature: float) -> Dict[str, Any]:
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        if self.referer:
            headers["HTTP-Referer"] = self.referer
        if self.title:
            headers["X-Title"] = self.title

        response = httpx.post(f"{self.base_url}/chat/completions",
                              headers=headers,
                              json=payload,
                              timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        if "error" in data:
            raise RuntimeError(f"OpenRouter error: {data['error']}")
        try:
            choice = data["choices"][0]
            message = choice["message"]
        except (KeyError, IndexError, TypeError) as exc:  # pragma: no cover - defensive
            raise RuntimeError("Malformed response from OpenRouter") from exc
        return message


class APKAgent:
    """Small ReAct-style agent that can inspect/edit an unpacked APK tree."""

    def __init__(self,
                 *,
                 workspace: Path,
                 metadata: APKMetadata,
                 client: OpenRouterClient,
                 model: str,
                 instructions: str,
                 max_steps: int,
                 temperature: float,
                 console: Optional[Console] = None) -> None:
        self.workspace = workspace
        self.metadata = metadata
        self.client = client
        self.model = model
        self.instructions = instructions.strip()
        self.max_steps = max_steps
        self.temperature = temperature
        self.console = console
        self._messages: List[Dict[str, str]] = []
        self._dirty = False

    def run(self) -> AgentRunResult:
        self._messages = self._bootstrap_messages()
        steps = 0
        while steps < self.max_steps:
            steps += 1
            if self.console:
                self.console.print(f"[cyan]Agent step {steps}/{self.max_steps}…[/cyan]")
            reply = self.client.chat(messages=self._messages,
                                     model=self.model,
                                     temperature=self.temperature)
            content = (reply.get("content") or "").strip()
            if not content:
                raise RuntimeError("LLM returned an empty response")
            self._messages.append({"role": "assistant", "content": content})
            directive = self._parse_agent_directive(content)
            action = directive.get("action")
            if action == "call_tool":
                tool = directive.get("tool")
                arguments = directive.get("arguments") or {}
                tool_message = self._run_tool(tool, arguments)
                self._messages.append({"role": "user", "content": tool_message})
                continue
            if action == "final":
                summary = directive.get("summary", "")
                changelog = directive.get("changelog") or []
                if not isinstance(changelog, list):
                    changelog = [str(changelog)]
                return AgentRunResult(steps=steps,
                                      summary=summary,
                                      changelog=[str(item) for item in changelog if item],
                                      modified=self._dirty)
            raise RuntimeError("Agent produced an unsupported action")
        raise RuntimeError("Agent stopped after reaching the maximum step limit")

    # ------------------------------------------------------------------
    # Prompt bootstrap helpers
    # ------------------------------------------------------------------

    def _bootstrap_messages(self) -> List[Dict[str, str]]:
        system_prompt = self._build_system_prompt()
        seed_payload = {
            "mission": self.instructions,
            "apk_metadata": self._metadata_payload(),
            "workspace": {
                "root": str(self.workspace),
                "tree_sample": self._tree_snapshot(limit=80),
            },
        }
        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(seed_payload, indent=2)},
        ]

    def _build_system_prompt(self) -> str:
        tool_spec = textwrap.dedent(
            """
            Reply with JSON only. Obey this schema:
            - Call a tool: {"action": "call_tool", "tool": "list_dir", "arguments": {...}}
            - Finish the task: {"action": "final", "summary": "...", "changelog": ["..."]}

            Tools you can call:
            1. describe_apk() -> return cached manifest + signing metadata. Args: none.
            2. list_dir(path=".", pattern="**/*", limit=50, files_only=false, recursive=true) -> show entries inside a directory.
            3. read_text(path, offset=0, max_bytes=4096) -> read part of a UTF-8 file. Use offset+max_bytes to paginate.
            4. write_text(path, content, mode="overwrite"|"append") -> write UTF-8 text files. Creates parents.
            5. delete_path(path) -> delete a file or a directory tree.

            Rules:
            - All paths are relative to the workspace root.
            - Never assume file contents; inspect with read_text first.
            - Only edit plain-text assets (XML, JSON, smali, etc.). Refuse binary/Dex rewrites.
            - Keep write_text payloads reasonably small (<15000 chars).
            - Stay within {self.max_steps} tool invocations unless the user request is satisfied earlier.
            - When satisfied, call the final action with a short summary + bullet-like changelog strings.
            """
        ).strip()
        return tool_spec

    def _metadata_payload(self) -> Dict[str, Any]:
        certs = [
            {
                "subject": cert.subject,
                "issuer": cert.issuer,
                "not_before": cert.not_before.isoformat(),
                "not_after": cert.not_after.isoformat(),
                "sha256": cert.sha256,
            }
            for cert in self.metadata.certificates
        ]
        return {
            "package_name": self.metadata.package_name,
            "version_name": self.metadata.version_name,
            "version_code": self.metadata.version_code,
            "min_sdk": self.metadata.min_sdk,
            "target_sdk": self.metadata.target_sdk,
            "file_count": self.metadata.file_count,
            "archive_size": self.metadata.archive_size,
            "sha256": self.metadata.sha256,
            "certificates": certs,
        }

    def _tree_snapshot(self, *, limit: int) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        for path in sorted(self.workspace.rglob("*")):
            if len(entries) >= limit:
                break
            relative = path.relative_to(self.workspace).as_posix()
            if not relative:
                continue
            info = {
                "path": relative + ("/" if path.is_dir() else ""),
                "type": "dir" if path.is_dir() else "file",
            }
            if path.is_file():
                try:
                    info["size"] = path.stat().st_size
                except OSError:
                    info["size"] = None
            entries.append(info)
        return entries

    # ------------------------------------------------------------------
    # Tool execution helpers
    # ------------------------------------------------------------------

    def _run_tool(self, tool: Optional[str], arguments: Dict[str, Any]) -> str:
        if not tool:
            raise RuntimeError("Agent omitted the tool name")
        handlers = {
            "describe_apk": self._tool_describe_apk,
            "list_dir": self._tool_list_dir,
            "read_text": self._tool_read_text,
            "write_text": self._tool_write_text,
            "delete_path": self._tool_delete_path,
        }
        handler = handlers.get(tool)
        if handler is None:
            payload = {"tool": tool, "status": "error", "output": {"message": "Unknown tool"}}
            return json.dumps(payload, indent=2)
        try:
            output = handler(**arguments)
            payload = {"tool": tool, "status": "ok", "output": output}
        except Exception as exc:  # pragma: no cover - defensive wrapper
            if self.console:
                self.console.print(f"[red]Tool {tool} failed:[/red] {exc}")
            payload = {
                "tool": tool,
                "status": "error",
                "output": {"message": str(exc)},
            }
        return json.dumps(payload, indent=2, ensure_ascii=False)

    def _tool_describe_apk(self) -> Dict[str, Any]:
        return self._metadata_payload()

    def _tool_list_dir(self,
                       path: str = ".",
                       pattern: str = "**/*",
                       limit: int = 50,
                       files_only: bool = False,
                       recursive: bool = True) -> Dict[str, Any]:
        target = self._resolve_path(path)
        if target.is_file():
            raise ValueError("list_dir expects a directory path")
        if limit <= 0:
            raise ValueError("limit must be positive")
        pattern = pattern.strip() if pattern else "*"
        if pattern in {"", "."}:
            pattern = "*"
        if pattern.startswith("./"):
            pattern = pattern[2:] or "*"
        matches: List[Dict[str, Any]] = []
        iterator = target.rglob(pattern) if recursive else target.glob(pattern)
        for candidate in iterator:
            if candidate == target:
                continue
            if files_only and candidate.is_dir():
                continue
            entry = {
                "path": candidate.relative_to(self.workspace).as_posix() + ("/" if candidate.is_dir() else ""),
                "type": "dir" if candidate.is_dir() else "file",
            }
            if candidate.is_file():
                try:
                    entry["size"] = candidate.stat().st_size
                except OSError:
                    entry["size"] = None
            matches.append(entry)
            if len(matches) >= limit:
                break
        return {
            "path": path,
            "pattern": pattern,
            "recursive": recursive,
            "entries": matches,
            "truncated": len(matches) >= limit,
        }

    def _tool_read_text(self,
                        path: str,
                        offset: int = 0,
                        max_bytes: int = 4096) -> Dict[str, Any]:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        if offset < 0:
            raise ValueError("offset must be >= 0")
        target = self._resolve_path(path)
        if target.is_dir():
            raise ValueError("Cannot read a directory")
        total_size = target.stat().st_size
        if offset > total_size:
            raise ValueError("offset exceeds file size")
        with target.open("rb") as fh:
            fh.seek(offset)
            chunk = fh.read(max_bytes)
        text = chunk.decode("utf-8", errors="replace")
        return {
            "path": path,
            "offset": offset,
            "returned_bytes": len(chunk),
            "file_size": total_size,
            "truncated": offset + len(chunk) < total_size,
            "content": text,
        }

    def _tool_write_text(self,
                         path: str,
                         content: str,
                         mode: str = "overwrite") -> Dict[str, Any]:
        if not isinstance(content, str):
            raise ValueError("content must be a string")
        target = self._resolve_path(path, allow_create=True)
        target.parent.mkdir(parents=True, exist_ok=True)
        encoding = "utf-8"
        if mode not in {"overwrite", "append"}:
            raise ValueError("mode must be overwrite or append")
        data = content
        write_mode = "w" if mode == "overwrite" else "a"
        with target.open(write_mode, encoding=encoding) as fh:
            fh.write(data)
        self._dirty = True
        return {
            "path": path,
            "mode": mode,
            "chars_written": len(content),
        }

    def _tool_delete_path(self, path: str) -> Dict[str, Any]:
        target = self._resolve_path(path)
        if target == self.workspace:
            raise ValueError("Refusing to delete the workspace root")
        if target.is_dir():
            shutil.rmtree(target)
            deleted = "directory"
        elif target.exists():
            target.unlink()
            deleted = "file"
        else:
            raise FileNotFoundError(f"{path} does not exist")
        self._dirty = True
        return {"path": path, "deleted": deleted}

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _resolve_path(self, relative: str, *, allow_create: bool = False) -> Path:
        if not relative:
            relative = "."
        candidate = (self.workspace / relative).resolve()
        try:
            candidate.relative_to(self.workspace)
        except ValueError as exc:
            raise ValueError("Path escapes the workspace") from exc
        if not allow_create and not candidate.exists():
            raise FileNotFoundError(f"{relative} does not exist")
        return candidate

    @staticmethod
    def _parse_agent_directive(content: str) -> Dict[str, Any]:
        cleaned = content.strip()
        if cleaned.startswith("```"):
            cleaned = APKAgent._strip_code_fence(cleaned)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Agent response was not valid JSON") from exc

    @staticmethod
    def _strip_code_fence(block: str) -> str:
        lines = block.strip().splitlines()
        if not lines:
            return block
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        return "\n".join(lines)
