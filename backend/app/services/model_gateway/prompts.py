"""Task prompts and few-shot examples (DAST-02-060), loaded from files so prompt behaviour can
be tuned without code changes.

Layout under `app/data/dast/`:

    prompts/_preamble.md         shared ethical-testing preamble, prepended to every task
    prompts/<task>.md            one system prompt per gateway task
    dast_fewshot_examples.json   {task: [{"input": ..., "output": ...}, ...]}

A composed system prompt is `preamble + task prompt + examples + caller's extra system text`.
Examples are taken in file order and capped per task, so identical inputs compose identical
prompts and scans stay reproducible. Every file is validated at construction and a bad one raises
`PromptError` naming it, so a broken edit stops the application at startup rather than failing
mid-scan.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping, Sequence

from app.config import DAST_MODEL_TASKS

DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "dast"
PROMPTS_DIR = DATA_DIR / "prompts"
PREAMBLE_FILE = "_preamble.md"
FEWSHOT_FILE = "dast_fewshot_examples.json"
MAX_PROMPT_CHARS = 20_000


class PromptError(ValueError):
    """A prompt or example file is missing or invalid. `file` names it."""

    def __init__(self, file: str, message: str):
        self.file = file
        super().__init__(f"{file}: {message}")


def _read_prompt(path: Path) -> str:
    if not path.is_file():
        raise PromptError(path.name, "file is missing")
    try:
        text = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise PromptError(path.name, f"cannot be read as UTF-8 text ({exc})") from exc
    if not text:
        raise PromptError(path.name, "file is empty")
    if len(text) > MAX_PROMPT_CHARS:
        raise PromptError(path.name, f"is longer than {MAX_PROMPT_CHARS} characters")
    return text


def _read_examples(path: Path) -> dict[str, list[dict[str, Any]]]:
    if not path.is_file():
        raise PromptError(path.name, "file is missing")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PromptError(path.name, f"is not valid JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise PromptError(path.name, "must be an object keyed by task")
    blocks: dict[str, list[dict[str, Any]]] = {}
    for task, block in data.items():
        if task.startswith("_"):
            continue  # "_comment" and similar
        if task not in DAST_MODEL_TASKS:
            raise PromptError(path.name, f"has examples for unknown task {task!r}")
        if not isinstance(block, list):
            raise PromptError(path.name, f"block {task!r} must be a list")
        for index, example in enumerate(block):
            if not isinstance(example, dict) or "input" not in example or "output" not in example:
                raise PromptError(path.name, f"{task}[{index}] needs 'input' and 'output'")
        blocks[task] = block
    return blocks


@dataclass(frozen=True)
class PromptLibrary:
    preamble: str
    tasks: Mapping[str, str]
    examples: Mapping[str, Sequence[Mapping[str, Any]]]
    max_examples: int = 3

    @classmethod
    def load(
        cls,
        prompts_dir: Path = PROMPTS_DIR,
        fewshot_path: Path | None = None,
        max_examples: int = 3,
    ) -> "PromptLibrary":
        preamble = _read_prompt(prompts_dir / PREAMBLE_FILE)
        tasks = {task: _read_prompt(prompts_dir / f"{task}.md") for task in DAST_MODEL_TASKS}
        examples = _read_examples(fewshot_path or (DATA_DIR / FEWSHOT_FILE))
        return cls(preamble, tasks, examples, max(0, max_examples))

    def examples_for(self, task: str) -> list[Mapping[str, Any]]:
        return list(self.examples.get(task, ()))[: self.max_examples]

    def compose(self, task: str, extra: str = "") -> str:
        """The full system prompt for `task`. Raises KeyError for a task with no prompt file."""
        parts = [self.preamble, self.tasks[task]]
        shots = self.examples_for(task)
        if shots:
            rendered = "\n\n".join(
                f"Input: {json.dumps(s['input'], ensure_ascii=False, sort_keys=True)}\n"
                f"Output: {json.dumps(s['output'], ensure_ascii=False, sort_keys=True)}"
                for s in shots
            )
            parts.append("Examples of the expected reasoning, input to output:\n\n" + rendered)
        if extra and extra.strip():
            parts.append(extra.strip())
        return "\n\n".join(parts)


@lru_cache(maxsize=1)
def default_library() -> PromptLibrary:
    """Loaded once; the application calls this at startup so a bad file fails fast."""
    from app.config import settings

    return PromptLibrary.load(max_examples=settings.dast_fewshot_max_examples)
