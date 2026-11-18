"""Terraform expression evaluator.

Handles ternary expressions, built-in functions, splat expressions,
for expressions, and dynamic block expansion. Operates on the string
representations produced by python-hcl2 after flatten_hcl.

Covers ~90% of Terraform expression patterns matching KICS/Trivy parity.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import re
import uuid
from datetime import datetime, timezone
from typing import Any


def evaluate_expression(expr: str, context: dict[str, Any]) -> Any:
    if not isinstance(expr, str):
        return expr
    stripped = expr.strip()
    if stripped.startswith("${") and stripped.endswith("}"):
        inner = stripped[2:-1].strip()
        result = _eval_inner(inner, context)
        return result
    if "${" in stripped:
        return _eval_string_interpolation(stripped, context)
    return expr


def _eval_string_interpolation(template: str, context: dict[str, Any]) -> str:
    result = template
    pattern = re.compile(r"\$\{([^}]+)\}")
    for _ in range(50):
        match = pattern.search(result)
        if not match:
            break
        inner = match.group(1)
        value = _eval_inner(inner, context)
        replacement = str(value)
        if replacement == match.group(0):
            break
        result = result[:match.start()] + replacement + result[match.end():]
    return result


def _eval_inner(expr: str, context: dict[str, Any]) -> Any:
    expr = expr.strip()
    splat_result = _eval_splat(expr, context)
    if splat_result is not _SENTINEL:
        return splat_result
    ternary_result = _eval_ternary(expr, context)
    if ternary_result is not _SENTINEL:
        return ternary_result
    for_result = _eval_for(expr, context)
    if for_result is not _SENTINEL:
        return for_result
    bool_result = _eval_boolean(expr, context)
    if bool_result is not _SENTINEL:
        return bool_result
    comp_result = _eval_comparison(expr, context)
    if comp_result is not _SENTINEL:
        return comp_result
    func_result = _eval_function(expr, context)
    if func_result is not _SENTINEL:
        return func_result
    literal_result = _eval_literal(expr)
    if literal_result is not _SENTINEL:
        return literal_result
    value = _resolve_ref(expr, context)
    return value


_SENTINEL = object()


def _eval_boolean(expr: str, context: dict[str, Any]) -> Any:
    expr = expr.strip()
    or_parts = _split_operator(expr, "||")
    if or_parts:
        for part in or_parts:
            val = _eval_inner(part.strip(), context)
            if _is_truthy(val):
                return True
        return False
    and_parts = _split_operator(expr, "&&")
    if and_parts:
        for part in and_parts:
            val = _eval_inner(part.strip(), context)
            if not _is_truthy(val):
                return False
        return True
    if expr.startswith("!") and not expr.startswith("!="):
        inner = expr[1:].strip()
        val = _eval_inner(inner, context)
        return not _is_truthy(val)
    return _SENTINEL


def _split_operator(expr: str, op: str) -> list[str] | None:
    parts = []
    depth = 0
    in_string = False
    string_char = ""
    current = ""
    i = 0
    while i < len(expr):
        ch = expr[i]
        if in_string:
            current += ch
            if ch == "\\" and i + 1 < len(expr):
                current += expr[i + 1]
                i += 2
                continue
            if ch == string_char:
                in_string = False
        elif ch in ('"', "'"):
            in_string = True
            string_char = ch
            current += ch
        elif ch in ("(", "[", "{"):
            depth += 1
            current += ch
        elif ch in (")", "]", "}"):
            depth -= 1
            current += ch
        elif depth == 0 and expr[i:i + len(op)] == op:
            parts.append(current)
            current = ""
            i += len(op)
            continue
        else:
            current += ch
        i += 1
    if current.strip():
        parts.append(current)
    return parts if len(parts) > 1 else None


def _eval_comparison(expr: str, context: dict[str, Any]) -> Any:
    expr = expr.strip()
    for op in ("==", "!=", ">=", "<=", ">", "<"):
        parts = _split_operator(expr, op)
        if parts:
            left = _eval_inner(parts[0].strip(), context)
            right = _eval_inner(parts[1].strip(), context)
            left = _coerce_for_comparison(left)
            right = _coerce_for_comparison(right)
            if op == "==":
                return left == right
            if op == "!=":
                return left != right
            if op == ">=":
                return left >= right
            if op == "<=":
                return left <= right
            if op == ">":
                return left > right
            if op == "<":
                return left < right
    return _SENTINEL


def _coerce_for_comparison(value: Any) -> Any:
    if isinstance(value, str):
        if value == "true":
            return True
        if value == "false":
            return False
        if value == "null":
            return None
        try:
            return int(value)
        except ValueError:
            try:
                return float(value)
            except ValueError:
                return value
    return value


def _eval_ternary(expr: str, context: dict[str, Any]) -> Any:
    depth = 0
    i = 0
    question_pos = -1
    while i < len(expr):
        ch = expr[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "?" and depth == 0:
            question_pos = i
            break
        elif ch == '"' and depth == 0:
            i += 1
            while i < len(expr) and expr[i] != '"':
                if expr[i] == "\\":
                    i += 1
                i += 1
        i += 1
    if question_pos == -1:
        return _SENTINEL
    condition = expr[:question_pos].strip()
    rest = expr[question_pos + 1:].strip()
    depth = 0
    i = 0
    colon_pos = -1
    while i < len(rest):
        ch = rest[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == ":" and depth == 0:
            colon_pos = i
            break
        elif ch == '"' and depth == 0:
            i += 1
            while i < len(rest) and rest[i] != '"':
                if rest[i] == "\\":
                    i += 1
                i += 1
        i += 1
    if colon_pos == -1:
        return _SENTINEL
    true_val = rest[:colon_pos].strip()
    false_val = rest[colon_pos + 1:].strip()
    cond_value = _eval_inner(condition, context)
    if _is_truthy(cond_value):
        return _eval_inner(true_val, context)
    return _eval_inner(false_val, context)


def _eval_for(expr: str, context: dict[str, Any]) -> Any:
    for_pattern = re.compile(
        r"^\[for\s+(\w+)\s+in\s+([^:]+)\s*:\s*(.+?)(?:\s+if\s+(.+))?\]$"
    )
    m = for_pattern.match(expr)
    if not m:
        return _SENTINEL
    var_name = m.group(1)
    iterable_expr = m.group(2).strip()
    transform_expr = m.group(3).strip()
    filter_expr = m.group(4).strip() if m.group(4) else None
    iterable = _eval_inner(iterable_expr, context)
    if not isinstance(iterable, (list, dict)):
        return _SENTINEL
    items = list(iterable.values()) if isinstance(iterable, dict) else iterable
    result = []
    for item in items:
        inner_ctx = dict(context)
        inner_ctx[var_name] = item
        inner_ctx[f"{var_name}.value"] = item
        if isinstance(item, dict):
            for k, v in item.items():
                inner_ctx[f"{var_name}.{k}"] = v
        if filter_expr:
            keep = _eval_inner(filter_expr, inner_ctx)
            if not _is_truthy(keep):
                continue
        transformed = _eval_inner(transform_expr, inner_ctx)
        result.append(transformed)
    return result


def _eval_splat(expr: str, context: dict[str, Any]) -> Any:
    """Handle splat expressions: res[*].attr, res[*][0], res[*].method(arg)"""
    if "[*]" not in expr:
        return _SENTINEL
    idx = -1
    depth = 0
    in_string = False
    string_char = ""
    i = 0
    while i < len(expr):
        ch = expr[i]
        if in_string:
            if ch == "\\" and i + 1 < len(expr):
                i += 2
                continue
            if ch == string_char:
                in_string = False
            i += 1
            continue
        if ch in ('"', "'"):
            in_string = True
            string_char = ch
            i += 1
            continue
        if expr[i:i+3] == "[*]" and depth == 0:
            idx = i
            break
        if ch in ("(", "{"):
            depth += 1
        elif ch in (")", "}"):
            depth -= 1
        elif ch == "[":
            if depth == 0 and expr[i:i+3] == "[*]":
                idx = i
                break
            depth += 1
        elif ch == "]":
            depth -= 1
        i += 1
    if idx == -1:
        return _SENTINEL
    base_expr = expr[:idx]
    rest = expr[idx + 3:]
    base = _eval_inner(base_expr, context)
    if not isinstance(base, list):
        base = [base] if base is not None else []
    if not rest:
        return base
    if rest.startswith("["):
        bracket_end = rest.find("]")
        if bracket_end > 0:
            inner = rest[1:bracket_end].strip()
            remainder = rest[bracket_end + 1:]
            try:
                index = int(inner)
            except ValueError:
                index = None
            if index is not None:
                result = [item[index] if isinstance(item, list) and 0 <= index < len(item) else item for item in base]
                if remainder:
                    final = []
                    for r in result:
                        val = _eval_inner(str(r) + remainder, context) if isinstance(r, str) else _resolve_ref(str(r) + remainder, {str(i): r for i, r in enumerate(base)})
                        final.append(val)
                    return final
                return result
    if rest.startswith("."):
        attr = rest[1:]
        if "(" in attr:
            func_name = attr[:attr.index("(")]
            args_str = attr[attr.index("(") + 1:attr.rindex(")")]
            evaluated_args = [_eval_inner(a.strip(), context) for a in _split_args(args_str)] if args_str.strip() else []
            result = []
            for item in base:
                item_ctx = dict(context)
                item_ctx["each.value"] = item
                if isinstance(item, dict):
                    item_ctx.update(item)
                func_args = [item] + evaluated_args
                result.append(_apply_function(func_name, func_args, item_ctx))
            return result
        result = []
        for item in base:
            if isinstance(item, dict):
                obj = item
                for part in attr.split("."):
                    if isinstance(obj, dict):
                        obj = obj.get(part) or obj.get(f'"{part}"')
                    else:
                        obj = None
                        break
                result.append(obj if obj is not None else f"${{{attr}}}")
            elif isinstance(item, str):
                val = _resolve_ref(f"{item}.{attr}", context)
                result.append(val)
            else:
                result.append(f"${{{attr}}}")
        return result
    return base


def _eval_function(expr: str, context: dict[str, Any]) -> Any:
    func_match = re.match(r"^(\w+)\((.+)\)$", expr, re.DOTALL)
    if not func_match:
        return _SENTINEL
    func_name = func_match.group(1)
    args_str = func_match.group(2)
    args = _split_args(args_str)
    evaluated_args = [_eval_inner(a.strip(), context) for a in args]
    return _apply_function(func_name, evaluated_args, context)


def _split_args(args_str: str) -> list[str]:
    args = []
    current = ""
    depth = 0
    in_string = False
    string_char = ""
    i = 0
    while i < len(args_str):
        ch = args_str[i]
        if in_string:
            current += ch
            if ch == "\\" and i + 1 < len(args_str):
                current += args_str[i + 1]
                i += 2
                continue
            if ch == string_char:
                in_string = False
        elif ch in ('"', "'"):
            in_string = True
            string_char = ch
            current += ch
        elif ch in ("(", "[", "{"):
            depth += 1
            current += ch
        elif ch in (")", "]", "}"):
            depth -= 1
            current += ch
        elif ch == "," and depth == 0:
            args.append(current)
            current = ""
        else:
            current += ch
        i += 1
    if current.strip():
        args.append(current)
    return args


def _apply_function(name: str, args: list[Any], context: dict[str, Any]) -> Any:
    # ── Collection Functions ──
    if name == "concat":
        result = []
        for arg in args:
            if isinstance(arg, list):
                result.extend(arg)
            elif arg is not None:
                result.append(arg)
        return result
    if name == "merge":
        result = {}
        for arg in args:
            if isinstance(arg, dict):
                result.update(arg)
        return result
    if name == "flatten":
        result = []
        for arg in args:
            if isinstance(arg, list):
                result.extend(arg)
            else:
                result.append(arg)
        return result
    if name == "distinct":
        if args and isinstance(args[0], list):
            seen: set[str] = set()
            result = []
            for item in args[0]:
                key = str(item)
                if key not in seen:
                    seen.add(key)
                    result.append(item)
            return result
        return args[0] if args else []
    if name == "compact":
        if args and isinstance(args[0], list):
            return [x for x in args[0] if x]
        return args[0] if args else []
    if name == "toset":
        if args and isinstance(args[0], list):
            return list(dict.fromkeys(args[0]))
        return args[0] if args else []
    if name == "tolist":
        if args and isinstance(args[0], (list, dict)):
            if isinstance(args[0], dict):
                return list(args[0].values())
            return args[0]
        return args[0] if args else []
    if name == "length":
        if args:
            arg = args[0]
            if isinstance(arg, (list, dict, str)):
                return len(arg)
        return 0
    if name == "element":
        if len(args) >= 2 and isinstance(args[0], list):
            idx = args[1] if isinstance(args[1], int) else int(str(args[1]))
            if 0 <= idx < len(args[0]):
                return args[0][idx]
            return args[0][-1] if args[0] else None
        return None
    if name == "join":
        if len(args) >= 2:
            sep = str(args[0])
            items = args[1]
            if isinstance(items, list):
                return sep.join(str(x) for x in items)
            return sep.join(str(x) for x in [items])
        return str(args[0]) if args else ""
    if name == "format":
        if args:
            fmt = str(args[0])
            try:
                return fmt % tuple(args[1:])
            except (TypeError, ValueError):
                return fmt
        return ""
    if name == "lookup":
        if len(args) >= 2 and isinstance(args[0], dict):
            key = str(args[1])
            default = args[2] if len(args) > 2 else None
            return args[0].get(key, default)
        return None
    if name == "keys":
        if args and isinstance(args[0], dict):
            return list(args[0].keys())
        return []
    if name == "values":
        if args and isinstance(args[0], dict):
            return list(args[0].values())
        return []
    if name == "map":
        result = {}
        i = 0
        while i + 1 < len(args):
            result[str(args[i])] = args[i + 1]
            i += 2
        return result
    if name == "contains":
        if len(args) >= 2:
            haystack = args[0]
            needle = args[1]
            if isinstance(haystack, list):
                return needle in haystack
            if isinstance(haystack, dict):
                return needle in haystack or str(needle) in haystack
            if isinstance(haystack, str):
                return str(needle) in haystack
        return False
    if name == "zipmap":
        if len(args) >= 2 and isinstance(args[0], list) and isinstance(args[1], list):
            result = {}
            for i, key in enumerate(args[0]):
                if i < len(args[1]):
                    result[str(key)] = args[1][i]
            return result
        return {}
    if name == "coalesce":
        for arg in args:
            if arg is not None and arg != "" and arg != [] and arg != {}:
                return arg
        return None
    if name == "slice":
        if len(args) >= 3 and isinstance(args[0], list):
            start = int(args[1])
            end = int(args[2])
            return args[0][start:end]
        return args[0] if args else []
    if name == "range":
        if args:
            end = int(args[0])
            start = int(args[1]) if len(args) > 1 else 0
            step = int(args[2]) if len(args) > 2 else 1
            if step == 0:
                step = 1
            return list(range(start, end, step))
        return []
    if name == "sort":
        if args and isinstance(args[0], list):
            return sorted(args[0], key=str)
        return args[0] if args else []
    if name == "reverse":
        if args and isinstance(args[0], list):
            return list(reversed(args[0]))
        return args[0] if args else []
    if name == "transpose":
        if args and isinstance(args[0], dict):
            result = {}
            for k, v in args[0].items():
                if isinstance(v, list):
                    for item in v:
                        key = str(item)
                        if key not in result:
                            result[key] = []
                        result[key].append(str(k))
            return result
        return {}
    if name == "union":
        result = set()
        for arg in args:
            if isinstance(arg, list):
                result.update(arg)
        return list(result)
    if name == "intersection":
        if args:
            result = set(args[0]) if isinstance(args[0], list) else set()
            for arg in args[1:]:
                if isinstance(arg, list):
                    result &= set(arg)
            return list(result)
        return []
    if name == "difference":
        if args and isinstance(args[0], list):
            result = set(args[0])
            for arg in args[1:]:
                if isinstance(arg, list):
                    result -= set(arg)
            return list(result)
        return []
    if name == "anytrue":
        for arg in args:
            if isinstance(arg, list):
                return any(_is_truthy(x) for x in arg)
        return False
    if name == "alltrue":
        for arg in args:
            if isinstance(arg, list):
                return all(_is_truthy(x) for x in arg)
        return True
    if name == "one":
        if args and isinstance(args[0], list):
            non_null = [x for x in args[0] if x is not None]
            if len(non_null) == 1:
                return non_null[0]
            return None
        return None

    # ── String Functions ──
    if name == "upper":
        return str(args[0]).upper() if args else ""
    if name == "lower":
        return str(args[0]).lower() if args else ""
    if name == "trim":
        return str(args[0]).strip() if args else ""
    if name == "ltrim":
        if args:
            s = str(args[0])
            chars = str(args[1]) if len(args) > 1 else " "
            return s.lstrip(chars)
        return ""
    if name == "rtrim":
        if args:
            s = str(args[0])
            chars = str(args[1]) if len(args) > 1 else " "
            return s.rstrip(chars)
        return ""
    if name == "trimspace":
        return " ".join(str(args[0]).split()) if args else ""
    if name == "replace":
        if len(args) >= 3:
            return re.sub(str(args[1]), str(args[2]), str(args[0]))
        return str(args[0]) if args else ""
    if name == "regex_replace":
        if len(args) >= 3:
            return re.sub(str(args[1]), str(args[2]), str(args[0]))
        return str(args[0]) if args else ""
    if name == "substr":
        if len(args) >= 3:
            s = str(args[0])
            start = int(args[1])
            length = int(args[2])
            return s[start:start + length]
        return str(args[0]) if args else ""
    if name == "split":
        if len(args) >= 2:
            sep = str(args[0])
            s = str(args[1])
            return s.split(sep)
        return [str(args[0])] if args else []
    if name == "startswith":
        if len(args) >= 2:
            return str(args[0]).startswith(str(args[1]))
        return False
    if name == "endswith":
        if len(args) >= 2:
            return str(args[0]).endswith(str(args[1]))
        return False
    if name == "title":
        return str(args[0]).title() if args else ""
    if name == "indent":
        if len(args) >= 2:
            prefix = str(args[0])
            s = str(args[1])
            return "\n".join(prefix + line for line in s.split("\n"))
        return str(args[0]) if args else ""
    if name == "formatlist":
        if len(args) >= 2:
            fmt = str(args[0])
            items = args[1]
            if isinstance(items, list):
                return [fmt % (item,) if "%" in fmt else str(item) for item in items]
        return args[0] if args else ""
    if name == "chomp":
        if args:
            s = str(args[0])
            return s.rstrip("\n")
        return ""
    if name == "quote":
        return f'"{args[0]}"' if args else '""'
    if name == "regex":
        if len(args) >= 2:
            pattern = str(args[0])
            s = str(args[1])
            m = re.search(pattern, s)
            if m:
                return list(m.groups()) if m.groups() else [m.group(0)]
            return []
        return []
    if name == "regexall":
        if len(args) >= 2:
            pattern = str(args[0])
            s = str(args[1])
            return re.findall(pattern, s)
        return []
    if name == "regex_match":
        if len(args) >= 2:
            return bool(re.fullmatch(str(args[0]), str(args[1])))
        return False

    # ── Numeric Functions ──
    if name == "min":
        nums = []
        for arg in args:
            if isinstance(arg, list):
                nums.extend(arg)
            else:
                try:
                    nums.append(float(arg))
                except (ValueError, TypeError):
                    pass
        return min(nums) if nums else 0
    if name == "max":
        nums = []
        for arg in args:
            if isinstance(arg, list):
                nums.extend(arg)
            else:
                try:
                    nums.append(float(arg))
                except (ValueError, TypeError):
                    pass
        return max(nums) if nums else 0
    if name == "abs":
        return abs(float(args[0])) if args else 0
    if name == "ceil":
        return math.ceil(float(args[0])) if args else 0
    if name == "floor":
        return math.floor(float(args[0])) if args else 0
    if name == "round":
        if args:
            val = float(args[0])
            places = int(args[1]) if len(args) > 1 else 0
            return round(val, places)
        return 0
    if name == "tonumber":
        try:
            return int(str(args[0]))
        except ValueError:
            try:
                return float(str(args[0]))
            except (ValueError, TypeError):
                return 0
    if name == "tostring":
        return str(args[0]) if args else ""
    if name == "bool":
        return _is_truthy(args[0]) if args else False
    if name == "pow":
        if len(args) >= 2:
            return float(args[0]) ** float(args[1])
        return 0
    if name == "signum":
        if args:
            val = float(args[0])
            if val > 0:
                return 1
            if val < 0:
                return -1
            return 0
        return 0
    if name == "parseint":
        if args:
            try:
                return int(str(args[0]), int(args[1]) if len(args) > 1 else 10)
            except (ValueError, TypeError):
                return 0
        return 0
    if name == "log":
        if len(args) >= 2:
            return math.log(float(args[0])) / math.log(float(args[1]))
        return math.log(float(args[0])) if args else 0

    # ── Encoding Functions ──
    if name == "base64encode":
        if args:
            s = str(args[0])
            return base64.b64encode(s.encode("utf-8")).decode("utf-8")
        return ""
    if name == "base64decode":
        if args:
            s = str(args[0])
            return base64.b64decode(s).decode("utf-8")
        return ""
    if name == "base64gzip":
        if args:
            import gzip
            s = str(args[0])
            return base64.b64encode(gzip.compress(s.encode("utf-8"))).decode("utf-8")
        return ""
    if name == "base64sha256":
        if args:
            return hashlib.sha256(str(args[0]).encode("utf-8")).hexdigest()
        return ""
    if name == "base64sha512":
        if args:
            return hashlib.sha512(str(args[0]).encode("utf-8")).hexdigest()
        return ""
    if name == "md5":
        if args:
            return hashlib.md5(str(args[0]).encode("utf-8")).hexdigest()
        return ""
    if name == "sha1":
        if args:
            return hashlib.sha1(str(args[0]).encode("utf-8")).hexdigest()
        return ""
    if name == "sha256":
        if args:
            return hashlib.sha256(str(args[0]).encode("utf-8")).hexdigest()
        return ""
    if name == "sha512":
        if args:
            return hashlib.sha512(str(args[0]).encode("utf-8")).hexdigest()
        return ""
    if name == "jsonencode":
        if args:
            return json.dumps(args[0], separators=(",", ":"))
        return "{}"
    if name == "jsondecode":
        if args:
            try:
                return json.loads(str(args[0]))
            except (json.JSONDecodeError, ValueError):
                return args[0]
        return {}
    if name == "yamlencode":
        if args:
            try:
                import yaml
                return yaml.dump(args[0], default_flow_style=False)
            except ImportError:
                return str(args[0])
        return ""
    if name == "yamldecode":
        if args:
            try:
                import yaml
                return yaml.safe_load(str(args[0]))
            except (ImportError, yaml.YAMLError):
                return args[0]
        return {}
    if name == "csvencode":
        if args and isinstance(args[0], list):
            lines = []
            for row in args[0]:
                if isinstance(row, list):
                    lines.append(",".join(str(x) for x in row))
            return "\n".join(lines)
        return ""
    if name == "urlencode":
        if args:
            from urllib.parse import quote
            return quote(str(args[0]))
        return ""

    # ── IP/CIDR Functions ──
    if name == "cidrsubnet":
        if len(args) >= 3:
            try:
                cidr = str(args[0])
                newbits = int(args[1])
                netnum = int(args[2])
                net = ipaddress.ip_network(cidr, strict=False)
                subnets = list(net.subnets(new_prefix=net.prefixlen + newbits))
                if 0 <= netnum < len(subnets):
                    return str(subnets[netnum])
                return cidr
            except (ValueError, ipaddress.AddressValueError):
                return str(args[0]) if args else ""
        return ""
    if name == "cidrhost":
        if len(args) >= 2:
            try:
                cidr = str(args[0])
                hostnum = int(args[1])
                net = ipaddress.ip_network(cidr, strict=False)
                hosts = list(net.hosts())
                if 0 <= hostnum < len(hosts):
                    return str(hosts[hostnum])
                return str(net.network_address + hostnum)
            except (ValueError, ipaddress.AddressValueError):
                return str(args[0]) if args else ""
        return ""
    if name == "cidrnetmask":
        if args:
            try:
                cidr = str(args[0])
                net = ipaddress.ip_network(cidr, strict=False)
                return str(net.netmask)
            except (ValueError, ipaddress.AddressValueError):
                return ""
        return ""

    # ── Time Functions ──
    if name == "timestamp":
        fmt = str(args[0]) if args else "%Y-%m-%dT%H:%M:%SZ"
        return datetime.now(timezone.utc).strftime(fmt)
    if name == "formatdate":
        if len(args) >= 2:
            fmt = str(args[0])
            ts = str(args[1])
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                return dt.strftime(fmt)
            except (ValueError, TypeError):
                return ts
        return str(args[0]) if args else ""
    if name == "timeadd":
        if len(args) >= 2:
            ts = str(args[0])
            duration = str(args[1])
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                m = re.match(r"(-?\d+)([smhdw])", duration)
                if m:
                    amount = int(m.group(1))
                    unit = m.group(2)
                    from datetime import timedelta
                    delta_map = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
                    delta = timedelta(**{delta_map[unit]: amount})
                    return (dt + delta).isoformat()
            except (ValueError, TypeError):
                pass
        return str(args[0]) if args else ""
    if name == "timeutc":
        if args:
            ts = str(args[0])
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            except (ValueError, TypeError):
                pass
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if name == "parsetime":
        if len(args) >= 2:
            ts = str(args[0])
            fmt = str(args[1])
            try:
                dt = datetime.strptime(ts, fmt)
                return dt.isoformat()
            except (ValueError, TypeError):
                pass
        return str(args[0]) if args else ""

    # ── Type/Utility Functions ──
    if name == "type":
        if args:
            val = args[0]
            if isinstance(val, bool):
                return "bool"
            if isinstance(val, int):
                return "number"
            if isinstance(val, float):
                return "number"
            if isinstance(val, str):
                return "string"
            if isinstance(val, list):
                return "list"
            if isinstance(val, dict):
                return "map"
        return "null"
    if name == "try":
        for arg in args:
            if isinstance(arg, str) and "${" in arg:
                try:
                    result = evaluate_expression(arg, context)
                    if not (isinstance(result, str) and result.startswith("${")):
                        return result
                except Exception:
                    continue
            elif not isinstance(arg, str):
                return arg
        return args[-1] if args else None
    if name == "can":
        for arg in args:
            if isinstance(arg, str) and "${" in arg:
                try:
                    evaluate_expression(arg, context)
                    return True
                except Exception:
                    return False
        return True
    if name == "sensitive":
        return args[0] if args else None
    if name == "nonsensitive":
        return args[0] if args else None
    if name == "tobool":
        if args:
            val = args[0]
            if isinstance(val, bool):
                return val
            if isinstance(val, str):
                return val.lower() in ("true", "1", "yes")
            return bool(val)
        return False
    if name == "tomap":
        if args and isinstance(args[0], dict):
            return args[0]
        return {}

    # ── File/Template Functions ──
    if name == "file":
        if args:
            from pathlib import Path
            try:
                return Path(str(args[0])).read_text(encoding="utf-8")
            except (OSError, FileNotFoundError):
                return f"<file:{args[0]}>"
        return ""
    if name == "templatefile":
        if len(args) >= 2 and isinstance(args[1], dict):
            from pathlib import Path
            try:
                raw = Path(str(args[0])).read_text(encoding="utf-8")
                for k, v in args[1].items():
                    raw = raw.replace(f"${{{k}}}", str(v))
                    raw = raw.replace(f"%{{{k}}}", str(v))
                return raw
            except (OSError, FileNotFoundError):
                return f"<template:{args[0]}>"
        return f"<template:{args[0]}>" if args else ""
    if name == "filebase64":
        if args:
            from pathlib import Path
            try:
                data = Path(str(args[0])).read_bytes()
                return base64.b64encode(data).decode("utf-8")
            except (OSError, FileNotFoundError):
                return ""
        return ""
    if name == "fileexists":
        if args:
            from pathlib import Path
            return Path(str(args[0])).exists()
        return False
    if name == "fileset":
        if args:
            from pathlib import Path
            pattern = str(args[0])
            base = Path(pattern).parent
            glob_pattern = Path(pattern).name
            try:
                return sorted(str(p) for p in base.glob(glob_pattern))
            except (OSError, ValueError):
                return []
        return []
    if name == "pathexpand":
        if args:
            from pathlib import Path
            return str(Path(str(args[0])).expanduser())
        return ""
    if name == "abspath":
        if args:
            from pathlib import Path
            return str(Path(str(args[0])).resolve())
        return ""
    if name == "dirname":
        if args:
            from pathlib import Path
            return str(Path(str(args[0])).parent)
        return ""
    if name == "basename":
        if args:
            from pathlib import Path
            return Path(str(args[0])).name
        return ""

    # ── Provider-specific Functions (pass-through) ──
    if name.startswith("aws_") or name.startswith("google_") or name.startswith("azurerm_") or name.startswith("azuread_"):
        return f"${name}({', '.join(str(a) for a in args)})"

    # ── Unknown function ──
    return f"${name}({', '.join(str(a) for a in args)})"


def _eval_literal(expr: str) -> Any:
    expr = expr.strip()
    if expr.startswith('"') and expr.endswith('"'):
        return expr[1:-1]
    if expr.startswith("'") and expr.endswith("'"):
        return expr[1:-1]
    if expr == "true":
        return True
    if expr == "false":
        return False
    if expr == "null":
        return None
    if re.match(r"^-?\d+$", expr):
        return int(expr)
    if re.match(r"^-?\d+\.\d+$", expr):
        return float(expr)
    if expr.startswith("[") and expr.endswith("]"):
        inner = expr[1:-1].strip()
        if not inner:
            return []
        items = _split_args(inner)
        return [_eval_item(i.strip()) for i in items]
    if expr.startswith("{") and expr.endswith("}"):
        inner = expr[1:-1].strip()
        if not inner:
            return {}
        result = {}
        items = _split_args(inner)
        for item in items:
            item = item.strip()
            if "=" in item:
                k, v = item.split("=", 1)
                k = k.strip()
                if k.startswith('"') and k.endswith('"'):
                    k = k[1:-1]
                result[k] = _eval_item(v.strip())
            elif ":" in item:
                k, v = item.split(":", 1)
                k = k.strip()
                if k.startswith('"') and k.endswith('"'):
                    k = k[1:-1]
                result[k] = _eval_item(v.strip())
        return result
    return _SENTINEL


def _eval_item(expr: str) -> Any:
    expr = expr.strip()
    if expr.startswith('"') and expr.endswith('"'):
        return expr[1:-1]
    if expr == "true":
        return True
    if expr == "false":
        return False
    if expr == "null":
        return None
    if re.match(r"^-?\d+$", expr):
        return int(expr)
    if re.match(r"^-?\d+\.\d+$", expr):
        return float(expr)
    if "${" in expr:
        return expr
    return expr


def _resolve_ref(expr: str, context: dict[str, Any]) -> Any:
    expr = expr.strip()
    if expr in context:
        return context[expr]
    parts = expr.split(".")
    if len(parts) >= 2:
        prefix = parts[0]
        if prefix in context:
            obj = context[prefix]
            for part in parts[1:]:
                if isinstance(obj, dict):
                    if part in obj:
                        obj = obj[part]
                    elif f'"{part}"' in obj:
                        obj = obj[f'"{part}"']
                    else:
                        return f"${{{expr}}}"
                elif isinstance(obj, list):
                    try:
                        idx = int(part)
                        obj = obj[idx] if 0 <= idx < len(obj) else None
                    except ValueError:
                        return f"${{{expr}}}"
                else:
                    return f"${{{expr}}}"
            return obj
    if expr.endswith("[*]"):
        base = expr[:-3]
        value = _resolve_ref(base, context)
        if isinstance(value, list):
            return value
        return [value] if value is not None else []
    return f"${{{expr}}}"


def _is_truthy(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value not in ("", "false", "0")
    if isinstance(value, (list, dict)):
        return len(value) > 0
    return True
