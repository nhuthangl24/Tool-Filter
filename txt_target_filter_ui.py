from __future__ import annotations

import argparse
import difflib
import http.cookiejar
import json
import os
import re
import shutil
import threading
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from tkinter import StringVar, Tk, filedialog, messagebox
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from urllib.request import HTTPCookieProcessor, Request, build_opener, urlopen


CSS_EXTENSIONS = {".css"}
MEDIA_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".webp",
    ".svg",
    ".bmp",
    ".ico",
    ".mp4",
    ".mov",
    ".avi",
    ".mkv",
    ".webm",
    ".mp3",
    ".wav",
    ".m4a",
    ".aac",
    ".flac",
}
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
RAW_PAIR_PATTERN = re.compile(
    r"\b((?:\d{1,3}\.){3}\d{1,3})\b(?:\s*[:|-]?\s*)(/[^\s\"'<>]*)?"
)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FOCUS_TAGS = {"form", "input", "textarea", "select", "option", "button", "label"}
@dataclass(frozen=True)
class ParsedRecord:
    ip: str
    path: str
    source: str


@dataclass(frozen=True)
class TargetRecord:
    ip: str
    path: str
    source: str
    record_type: str
    line_number: int


def is_valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False

    for part in parts:
        if not part.isdigit():
            return False
        number = int(part)
        if number < 0 or number > 255:
            return False

    return True


def normalize_space(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def normalize_path(raw_path: str | None) -> str:
    if not raw_path:
        return "/"

    cleaned = raw_path.strip()
    if not cleaned.startswith("/"):
        cleaned = f"/{cleaned}"

    parsed = urlparse(cleaned)
    normalized = re.sub(r"/+", "/", parsed.path or "/")
    if normalized != "/" and normalized.endswith("/"):
        normalized = normalized.rstrip("/")

    return normalized or "/"


def path_with_query(raw_path: str | None) -> str:
    if not raw_path:
        return "/"

    cleaned = raw_path.strip()
    if not cleaned.startswith("/"):
        cleaned = f"/{cleaned}"

    parsed = urlparse(cleaned)
    path_only = normalize_path(parsed.path or "/")
    if parsed.query:
        return f"{path_only}?{parsed.query}"
    return path_only


def get_extension(request_path: str) -> str:
    parsed = urlparse(request_path)
    return Path(parsed.path).suffix.lower()


def is_media_path(request_path: str) -> bool:
    return get_extension(request_path) in MEDIA_EXTENSIONS


def sanitize_segment(segment: str) -> str:
    return re.sub(r'[<>:"\\|?*]', "_", segment)


def sanitize_file_stem(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "_", value)
    cleaned = cleaned.strip("._")
    return cleaned or "output"


def extract_record(line: str) -> ParsedRecord | None:
    original = line.strip()
    if not original:
        return None

    url_match = URL_PATTERN.search(original)
    if url_match:
        url_value = url_match.group(0)
        parsed = urlparse(url_value)
        hostname = parsed.hostname or ""
        if is_valid_ipv4(hostname):
            path_value = normalize_path(parsed.path or "/")
            if parsed.query:
                path_value = f"{path_value}?{parsed.query}"
            return ParsedRecord(ip=hostname, path=path_value, source=url_value)

    raw_pair_match = RAW_PAIR_PATTERN.search(original)
    if raw_pair_match:
        ip = raw_pair_match.group(1)
        raw_path = raw_pair_match.group(2) or "/"
        if is_valid_ipv4(ip):
            return ParsedRecord(ip=ip, path=path_with_query(raw_path), source=original)

    return None


def extract_targets_from_text(raw_value: str) -> set[str]:
    targets: set[str] = set()
    for match in IP_PATTERN.findall(raw_value):
        if is_valid_ipv4(match):
            targets.add(match)
    return targets


def load_target_filters(target_input: str | None) -> set[str] | None:
    if not target_input:
        return None

    cleaned = target_input.strip()
    if not cleaned:
        return None

    candidate_path = Path(cleaned).expanduser()
    if candidate_path.exists() and candidate_path.is_file():
        file_content = candidate_path.read_text(encoding="utf-8")
        targets = extract_targets_from_text(file_content)
    else:
        targets = extract_targets_from_text(cleaned)

    if not targets:
        raise ValueError("Input Target khong co IP hop le.")

    return targets


def path_signature(path_value: str) -> tuple[str, tuple[str, ...]]:
    parsed = urlparse(path_value)
    normalized_path = normalize_path(parsed.path or "/")
    param_names = tuple(sorted({key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}))
    return normalized_path, param_names


def build_media_manifest_path(media_root: Path, record: TargetRecord) -> Path:
    parsed = urlparse(record.path)
    segments = [sanitize_segment(segment) for segment in (parsed.path or "/").split("/") if segment]
    target_dir = media_root / sanitize_segment(record.ip)

    if not segments:
        target_dir.mkdir(parents=True, exist_ok=True)
        return target_dir / "root.path.txt"

    for segment in segments[:-1]:
        target_dir /= segment

    target_dir.mkdir(parents=True, exist_ok=True)
    return target_dir / f"{segments[-1]}.path.txt"


def build_target_file_path(targets_root: Path, ip: str) -> Path:
    return targets_root / f"{sanitize_segment(ip)}.txt"


def build_analysis_file_path(analysis_root: Path, base_url: str, target_file: Path) -> Path:
    parsed = urlparse(base_url)
    stem = parsed.netloc or target_file.stem
    return analysis_root / f"{sanitize_file_stem(stem)}.json"


def write_text_file(file_path: Path, lines: list[str] | str) -> None:
    payload = "\n".join(lines) if isinstance(lines, list) else str(lines)
    file_path.write_text(payload, encoding="utf-8")


def clean_filter_outputs(output_dir: Path) -> None:
    summary_file = output_dir / "summary.txt"
    if summary_file.exists():
        summary_file.unlink()

    for directory_name in ("media", "targets", "analysis"):
        directory = output_dir / directory_name
        if directory.exists():
            shutil.rmtree(directory)


def parse_txt_file(
    input_path: Path,
    output_dir: Path,
    target_filters: set[str] | None = None,
) -> dict[str, object]:
    input_path = input_path.expanduser().resolve()
    output_dir = output_dir.expanduser().resolve()

    lines = input_path.read_text(encoding="utf-8").splitlines()
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    kept_records: list[TargetRecord] = []
    css_skipped = 0
    duplicates_skipped = 0
    unparsable_lines = 0
    filter_skipped = 0
    query_paths_kept = 0
    plain_paths_kept = 0

    for index, line in enumerate(lines, start=1):
        parsed = extract_record(line)
        if not parsed:
            if line.strip():
                unparsable_lines += 1
            continue

        if target_filters is not None and parsed.ip not in target_filters:
            filter_skipped += 1
            continue

        record = TargetRecord(
            ip=parsed.ip,
            path=parsed.path,
            source=parsed.source,
            record_type="media" if is_media_path(parsed.path) else "path",
            line_number=index,
        )

        if get_extension(record.path) in CSS_EXTENSIONS:
            css_skipped += 1
            continue

        normalized_path, param_names = path_signature(record.path)
        dedupe_key = (record.ip, normalized_path, param_names)
        if dedupe_key in seen:
            duplicates_skipped += 1
            continue

        seen.add(dedupe_key)
        kept_records.append(record)
        if param_names:
            query_paths_kept += 1
        else:
            plain_paths_kept += 1

    output_dir.mkdir(parents=True, exist_ok=True)
    clean_filter_outputs(output_dir)

    media_records = [record for record in kept_records if record.record_type == "media"]
    unique_ips = list(dict.fromkeys(record.ip for record in kept_records))
    target_files: list[str] = []

    targets_root = output_dir / "targets"
    targets_root.mkdir(parents=True, exist_ok=True)
    for ip in unique_ips:
        ip_records = [record for record in kept_records if record.ip == ip]
        target_file = build_target_file_path(targets_root, ip)
        target_files.append(str(target_file))
        write_text_file(target_file, [record.path for record in ip_records])

    write_text_file(
        output_dir / "summary.txt",
        [
            f"input={input_path}",
            f"target_filter={','.join(sorted(target_filters)) if target_filters else 'ALL'}",
            f"total_lines={len(lines)}",
            f"targets_kept={len(kept_records)}",
            f"unique_ips={len(unique_ips)}",
            f"query_paths_kept={query_paths_kept}",
            f"plain_paths_kept={plain_paths_kept}",
            f"media_found={len(media_records)}",
            f"css_skipped={css_skipped}",
            f"duplicates_skipped={duplicates_skipped}",
            f"filter_skipped={filter_skipped}",
            f"unparsable_lines={unparsable_lines}",
        ],
    )

    media_root = output_dir / "media"
    for record in media_records:
        manifest_path = build_media_manifest_path(media_root, record)
        write_text_file(
            manifest_path,
            [
                f"ip={record.ip}",
                f"path={record.path}",
                f"source={record.source}",
                f"lineNumber={record.line_number}",
            ],
        )

    return {
        "lines": len(lines),
        "kept": len(kept_records),
        "unique_ips": len(unique_ips),
        "query_paths_kept": query_paths_kept,
        "plain_paths_kept": plain_paths_kept,
        "css_skipped": css_skipped,
        "duplicates_skipped": duplicates_skipped,
        "filter_skipped": filter_skipped,
        "media_found": len(media_records),
        "unparsable_lines": unparsable_lines,
        "output_dir": str(output_dir),
        "target_filter": ",".join(sorted(target_filters)) if target_filters else "ALL",
        "target_files": target_files,
    }


def fetch_url_text(url: str, timeout_seconds: float, opener=None) -> dict[str, object]:
    request = Request(url, headers={"User-Agent": "PathAudit/1.0"})
    request_opener = opener

    try:
        if request_opener is not None:
            response_handle = request_opener.open(request, timeout=timeout_seconds)
        else:
            response_handle = urlopen(request, timeout=timeout_seconds)

        with response_handle as response:
            status = response.getcode() or 200
            content_type = response.headers.get("Content-Type", "")
            charset = response.headers.get_content_charset() or "utf-8"
            body = response.read()
    except HTTPError as exc:
        return {
            "url": url,
            "status": exc.code,
            "content_type": "",
            "text": "",
            "error": f"HTTP {exc.code}",
        }
    except URLError as exc:
        return {
            "url": url,
            "status": None,
            "content_type": "",
            "text": "",
            "error": f"URL error: {exc.reason}",
        }
    except TimeoutError:
        return {
            "url": url,
            "status": None,
            "content_type": "",
            "text": "",
            "error": "Timeout",
        }

    try:
        text = body.decode(charset, errors="replace")
    except LookupError:
        text = body.decode("utf-8", errors="replace")

    return {
        "url": url,
        "status": status,
        "content_type": content_type,
        "text": text,
        "error": "",
    }


def response_looks_like_html(content_type: str, text: str) -> bool:
    content_type_lower = content_type.lower()
    text_lower = text.lower()
    return "html" in content_type_lower or "<html" in text_lower or "<body" in text_lower or "<form" in text_lower


def build_http_opener():
    cookie_jar = http.cookiejar.CookieJar()
    return build_opener(HTTPCookieProcessor(cookie_jar))


def resolve_login_url(base_url: str, login_url: str) -> str:
    cleaned = login_url.strip()
    if not cleaned:
        return base_url
    return urljoin(f"{base_url}/", cleaned)


def normalize_attrs(attrs: dict[str, str]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in sorted(attrs.items()):
        normalized[key.strip().lower()] = value.strip()
    return normalized


class LoginFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, object]] = []
        self.current_form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs_list: list[tuple[str, str | None]]) -> None:
        attrs = {key: value or "" for key, value in attrs_list}

        if tag == "form":
            self.current_form = {
                "action": attrs.get("action", ""),
                "method": attrs.get("method", "post").lower(),
                "inputs": [],
            }
            self.forms.append(self.current_form)
            return

        if self.current_form is None:
            return

        if tag != "input":
            return

        self.current_form["inputs"].append(
            {
                "type": (attrs.get("type") or "text").lower(),
                "name": attrs.get("name", ""),
                "value": attrs.get("value", ""),
            }
        )


def choose_login_form(forms: list[dict[str, object]]) -> dict[str, object] | None:
    for form in forms:
        inputs = list(form.get("inputs", []))
        if any(str(item.get("type", "")).lower() == "password" for item in inputs):
            return form
    return forms[0] if forms else None


def choose_username_field(inputs: list[dict[str, object]]) -> str | None:
    preferred_names = ("username", "user", "email", "login", "userid")
    for field_name in preferred_names:
        for item in inputs:
            item_name = str(item.get("name", "")).strip().lower()
            item_type = str(item.get("type", "")).strip().lower()
            if item_name == field_name and item_type in {"text", "email", ""}:
                return str(item.get("name", ""))

    for item in inputs:
        item_type = str(item.get("type", "")).strip().lower()
        if item_type in {"text", "email", ""} and str(item.get("name", "")).strip():
            return str(item.get("name", ""))
    return None


def choose_password_field(inputs: list[dict[str, object]]) -> str | None:
    for item in inputs:
        if str(item.get("type", "")).strip().lower() == "password" and str(item.get("name", "")).strip():
            return str(item.get("name", ""))
    return None


def login_with_credentials(
    opener,
    base_url: str,
    login_url: str,
    username: str,
    password: str,
    timeout_seconds: float,
) -> dict[str, object]:
    if not username or not password:
        return {
            "attempted": False,
            "success": False,
            "login_url": "",
            "error": "",
        }

    resolved_login_url = resolve_login_url(base_url, login_url)
    login_page = fetch_url_text(resolved_login_url, timeout_seconds, opener=opener)
    if login_page["error"]:
        return {
            "attempted": True,
            "success": False,
            "login_url": resolved_login_url,
            "error": str(login_page["error"]),
        }

    parser = LoginFormParser()
    parser.feed(str(login_page["text"]))
    form = choose_login_form(parser.forms)
    if form is None:
        return {
            "attempted": True,
            "success": False,
            "login_url": resolved_login_url,
            "error": "Khong tim thay login form co password field.",
        }

    inputs = list(form.get("inputs", []))
    username_field = choose_username_field(inputs)
    password_field = choose_password_field(inputs)
    if not username_field or not password_field:
        return {
            "attempted": True,
            "success": False,
            "login_url": resolved_login_url,
            "error": "Khong xac dinh duoc username/password field.",
        }

    payload: dict[str, str] = {}
    for item in inputs:
        name = str(item.get("name", "")).strip()
        if not name:
            continue
        payload[name] = str(item.get("value", ""))

    payload[username_field] = username
    payload[password_field] = password

    submit_url = urljoin(resolved_login_url, str(form.get("action", "") or ""))
    encoded_body = urlencode(payload).encode("utf-8")
    request = Request(
        submit_url,
        data=encoded_body,
        headers={
            "User-Agent": "PathAudit/1.0",
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": resolved_login_url,
        },
    )

    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            _ = response.read()
            status = response.getcode() or 200
    except HTTPError as exc:
        return {
            "attempted": True,
            "success": False,
            "login_url": resolved_login_url,
            "submit_url": submit_url,
            "status": exc.code,
            "error": f"HTTP {exc.code}",
        }
    except URLError as exc:
        return {
            "attempted": True,
            "success": False,
            "login_url": resolved_login_url,
            "submit_url": submit_url,
            "error": f"URL error: {exc.reason}",
        }
    except TimeoutError:
        return {
            "attempted": True,
            "success": False,
            "login_url": resolved_login_url,
            "submit_url": submit_url,
            "error": "Timeout",
        }

    return {
        "attempted": True,
        "success": True,
        "login_url": resolved_login_url,
        "submit_url": submit_url,
        "status": status,
        "username_field": username_field,
        "password_field": password_field,
        "error": "",
    }


class ElementSnapshotParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[dict[str, object]] = []
        self.stack: list[dict[str, object]] = []
        self.root_counts: dict[str, int] = {}

    def _next_path(self, tag: str) -> str:
        if not self.stack:
            index = self.root_counts.get(tag, 0) + 1
            self.root_counts[tag] = index
            return f"/{tag}[{index}]"

        parent = self.stack[-1]
        child_counts = parent.setdefault("child_counts", {})
        index = child_counts.get(tag, 0) + 1
        child_counts[tag] = index
        return f"{parent['path']}/{tag}[{index}]"

    def handle_starttag(self, tag: str, attrs_list: list[tuple[str, str | None]]) -> None:
        attrs = {key: value or "" for key, value in attrs_list}
        self.stack.append(
            {
                "tag": tag,
                "path": self._next_path(tag),
                "attrs": normalize_attrs(attrs),
                "text_parts": [],
                "child_counts": {},
            }
        )

    def handle_startendtag(self, tag: str, attrs_list: list[tuple[str, str | None]]) -> None:
        attrs = {key: value or "" for key, value in attrs_list}
        self.elements.append(
            {
                "path": self._next_path(tag),
                "tag": tag,
                "attrs": normalize_attrs(attrs),
                "text": "",
            }
        )

    def handle_data(self, data: str) -> None:
        if not self.stack:
            return

        text = normalize_space(data)
        if text:
            self.stack[-1]["text_parts"].append(text)

    def handle_endtag(self, tag: str) -> None:
        if not self.stack:
            return

        node = self.stack.pop()
        self.elements.append(
            {
                "path": node["path"],
                "tag": node["tag"],
                "attrs": node["attrs"],
                "text": normalize_space(" ".join(node["text_parts"]))[:500],
            }
        )


def element_payload(element: dict[str, object]) -> dict[str, object]:
    payload = {
        "tag": element["tag"],
        "attributes": element["attrs"],
    }
    text_value = str(element["text"]).strip()
    if text_value:
        payload["text"] = text_value
    return payload


def build_element_map(
    html_text: str,
    focus_tags: set[str] | None = None,
) -> dict[str, dict[str, object]]:
    parser = ElementSnapshotParser()
    parser.feed(html_text)
    filtered = parser.elements
    if focus_tags is not None:
        filtered = [element for element in filtered if str(element["tag"]).lower() in focus_tags]
    return {str(element["path"]): element for element in filtered}


def compare_html_documents(html_1: str, html_2: str) -> dict[str, object]:
    elements_1 = build_element_map(html_1, FOCUS_TAGS)
    elements_2 = build_element_map(html_2, FOCUS_TAGS)

    changed: list[dict[str, object]] = []
    only_in_url_1: list[dict[str, object]] = []
    only_in_url_2: list[dict[str, object]] = []

    for path in sorted(set(elements_1) | set(elements_2)):
        element_1 = elements_1.get(path)
        element_2 = elements_2.get(path)

        if element_1 and not element_2:
            only_in_url_1.append({"path": path, **element_payload(element_1)})
            continue
        if element_2 and not element_1:
            only_in_url_2.append({"path": path, **element_payload(element_2)})
            continue
        if element_1 and element_2 and element_payload(element_1) != element_payload(element_2):
            changed.append(
                {
                    "path": path,
                    "url_1": element_payload(element_1),
                    "url_2": element_payload(element_2),
                }
            )

    return {
        "mode": "html_focus_elements",
        "summary": {
            "elements_url_1": len(elements_1),
            "elements_url_2": len(elements_2),
            "changed_count": len(changed),
            "only_in_url_1_count": len(only_in_url_1),
            "only_in_url_2_count": len(only_in_url_2),
        },
        "differences": {
            "changed": changed,
            "only_in_url_1": only_in_url_1,
            "only_in_url_2": only_in_url_2,
        },
    }


def compare_text_documents(text_1: str, text_2: str) -> dict[str, object]:
    lines_1 = text_1.splitlines()
    lines_2 = text_2.splitlines()
    matcher = difflib.SequenceMatcher(a=lines_1, b=lines_2)
    blocks: list[dict[str, object]] = []

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        blocks.append(
            {
                "type": tag,
                "url_1_range": [i1 + 1, i2],
                "url_2_range": [j1 + 1, j2],
                "url_1_lines": lines_1[i1:i2],
                "url_2_lines": lines_2[j1:j2],
            }
        )

    return {
        "mode": "text_lines",
        "summary": {
            "lines_url_1": len(lines_1),
            "lines_url_2": len(lines_2),
            "difference_blocks": len(blocks),
        },
        "differences": {
            "blocks": blocks,
        },
    }


def extract_focus_elements(html_text: str) -> list[dict[str, object]]:
    element_map = build_element_map(html_text, FOCUS_TAGS)
    elements: list[dict[str, object]] = []
    for path, element in sorted(element_map.items()):
        elements.append(
            {
                "path": path,
                **element_payload(element),
            }
        )
    return elements


def load_paths_from_target_file(file_path: Path) -> list[str]:
    seen: set[str] = set()
    paths: list[str] = []

    for raw_line in file_path.read_text(encoding="utf-8").splitlines():
        cleaned = raw_line.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        paths.append(cleaned)

    return paths


def build_base_url(base_url: str) -> str:
    cleaned = base_url.strip().rstrip("/")
    parsed = urlparse(cleaned)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Base URL khong hop le. Vi du: http://192.168.144.155:3000")
    return cleaned


def build_page_url(base_url: str, path_value: str) -> str:
    return urljoin(f"{base_url}/", path_value.lstrip("/"))


def build_probe_variant_url(full_url: str) -> str:
    parsed = urlparse(full_url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if not pairs:
        raise ValueError("Path nay khong co query param de compare.")

    probe_pairs = [(key, f"codex_probe_{index + 1}") for index, (key, _) in enumerate(pairs)]
    return urlunparse(parsed._replace(query=urlencode(probe_pairs, doseq=True)))


def compare_live_urls(url_1: str, url_2: str, timeout_seconds: float, opener=None) -> dict[str, object]:
    response_1 = fetch_url_text(url_1, timeout_seconds, opener=opener)
    response_2 = fetch_url_text(url_2, timeout_seconds, opener=opener)

    if response_1["error"] or response_2["error"]:
        return {
            "mode": "error",
            "error": {
                "url_1": str(response_1["error"]),
                "url_2": str(response_2["error"]),
            },
        }

    text_1 = str(response_1["text"])
    text_2 = str(response_2["text"])
    if response_looks_like_html(str(response_1["content_type"]), text_1) or response_looks_like_html(
        str(response_2["content_type"]), text_2
    ):
        return compare_html_documents(text_1, text_2)
    return compare_text_documents(text_1, text_2)


def slim_compare_result(compare_result: dict[str, object]) -> dict[str, object]:
    mode = str(compare_result.get("mode", ""))
    if mode == "html_focus_elements":
        differences = compare_result.get("differences", {})
        if isinstance(differences, dict):
            merged: list[dict[str, object]] = []
            for item in differences.get("changed", []):
                if isinstance(item, dict):
                    merged.append(
                        {
                            "path": item.get("path", ""),
                            "original": item.get("url_1", {}),
                            "probe": item.get("url_2", {}),
                        }
                    )
            for item in differences.get("only_in_url_1", []):
                if isinstance(item, dict):
                    entry = dict(item)
                    entry.pop("path", None)
                    merged.append(
                        {
                            "path": item.get("path", ""),
                            "original": entry,
                        }
                    )
            for item in differences.get("only_in_url_2", []):
                if isinstance(item, dict):
                    entry = dict(item)
                    entry.pop("path", None)
                    merged.append(
                        {
                            "path": item.get("path", ""),
                            "probe": entry,
                        }
                    )
            return {
                "different_elements": merged,
            }
    if mode == "text_lines":
        differences = compare_result.get("differences", {})
        if isinstance(differences, dict):
            return {
                "different_blocks": list(differences.get("blocks", [])),
            }
    return {
        "error": compare_result.get("error", "Unable to compare one or both responses."),
    }


def analyze_target_paths(
    target_file: Path,
    base_url: str,
    output_dir: Path,
    login_url: str = "",
    username: str = "",
    password: str = "",
    timeout_seconds: float = 10.0,
) -> dict[str, object]:
    target_file = target_file.expanduser().resolve()
    output_dir = output_dir.expanduser().resolve()
    if not target_file.exists():
        raise FileNotFoundError(f"Khong tim thay target file: {target_file}")

    resolved_base_url = build_base_url(base_url)
    paths = load_paths_from_target_file(target_file)
    opener = build_http_opener()
    login_result = login_with_credentials(
        opener,
        resolved_base_url,
        login_url,
        username,
        password,
        timeout_seconds,
    )

    analysis_root = output_dir / "analysis"
    analysis_root.mkdir(parents=True, exist_ok=True)

    query_reports: list[dict[str, object]] = []
    plain_reports: list[dict[str, object]] = []
    fetch_errors = 0

    for path_value in paths:
        full_url = build_page_url(resolved_base_url, path_value)
        parsed = urlparse(full_url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)

        if query_pairs:
            probe_url = build_probe_variant_url(full_url)
            compare_result = compare_live_urls(full_url, probe_url, timeout_seconds, opener=opener)
            if compare_result.get("mode") == "error":
                fetch_errors += 1
            query_reports.append(
                {
                    "path": path_value,
                    "param_names": [key for key, _ in query_pairs],
                    **slim_compare_result(compare_result),
                }
            )
            continue

        response = fetch_url_text(full_url, timeout_seconds, opener=opener)
        report: dict[str, object] = {"path": path_value}

        if response["error"]:
            fetch_errors += 1
            report["error"] = response["error"]
            report["elements"] = []
        else:
            html_text = str(response["text"])
            if response_looks_like_html(str(response["content_type"]), html_text):
                report["elements"] = extract_focus_elements(html_text)
            else:
                report["elements"] = []
                report["note"] = "Skipped extraction because response is not HTML."

        plain_reports.append(report)

    payload: dict[str, object] = {}
    parsed_base = urlparse(resolved_base_url)
    payload["target"] = parsed_base.netloc or resolved_base_url
    if login_result.get("attempted") and login_result.get("error"):
        payload["login_error"] = login_result["error"]
    if query_reports:
        payload["query_paths"] = query_reports
    if plain_reports:
        payload["plain_paths"] = plain_reports

    output_file = build_analysis_file_path(analysis_root, resolved_base_url, target_file)
    output_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    return {
        "target_file": str(target_file),
        "base_url": resolved_base_url,
        "login_attempted": login_result["attempted"],
        "login_success": login_result["success"],
        "login_error": login_result["error"],
        "query_paths": len(query_reports),
        "plain_paths": len(plain_reports),
        "fetch_errors": fetch_errors,
        "output_file": str(output_file),
    }


class TargetFilterApp:
    def __init__(self, root: Tk) -> None:
        self.root = root
        self.root.title("TXT Target Filter")
        self.root.geometry("1060x780")
        self.root.minsize(900, 680)
        self.root.configure(bg="#f4efe6")

        self.filter_input_var = StringVar()
        self.filter_target_var = StringVar()
        self.filter_output_var = StringVar(value=str(Path.cwd() / "output"))
        self.analyze_target_file_var = StringVar()
        self.analyze_base_url_var = StringVar()
        self.analyze_login_url_var = StringVar()
        self.analyze_username_var = StringVar(value="admin")
        self.analyze_password_var = StringVar(value="password")
        self.analyze_output_var = StringVar(value=str(Path.cwd() / "output"))
        self.status_var = StringVar(value="Ready")

        self._configure_style()
        self._build_layout()

    def _configure_style(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("App.TFrame", background="#f4efe6")
        style.configure("Card.TFrame", background="#fffaf2")
        style.configure(
            "Title.TLabel",
            background="#f4efe6",
            foreground="#1f2933",
            font=("Segoe UI Semibold", 20),
        )
        style.configure(
            "Body.TLabel",
            background="#fffaf2",
            foreground="#334155",
            font=("Segoe UI", 10),
        )
        style.configure(
            "Status.TLabel",
            background="#f4efe6",
            foreground="#5b6470",
            font=("Segoe UI", 10),
        )
        style.configure("Accent.TButton", font=("Segoe UI Semibold", 10), padding=(16, 10))
        style.map(
            "Accent.TButton",
            background=[("active", "#cb7852"), ("!disabled", "#c86a42")],
            foreground=[("!disabled", "#ffffff")],
        )
        style.configure("Secondary.TButton", font=("Segoe UI", 10), padding=(12, 8))
        style.configure("TEntry", padding=(8, 8), fieldbackground="#ffffff")

    def _build_layout(self) -> None:
        wrapper = ttk.Frame(self.root, style="App.TFrame", padding=24)
        wrapper.pack(fill="both", expand=True)

        header = ttk.Frame(wrapper, style="App.TFrame")
        header.pack(fill="x", pady=(0, 18))
        ttk.Label(header, text="TXT Target Filter", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Tab 1 loc path theo target. Tab 2 scan file path da loc: path co query thi so sanh element khac nhau, khong co query thi lay form/input va full attribute.",
            style="Status.TLabel",
        ).pack(anchor="w", pady=(4, 0))

        notebook = ttk.Notebook(wrapper)
        notebook.pack(fill="x")

        filter_tab = ttk.Frame(notebook, style="Card.TFrame", padding=20)
        analyze_tab = ttk.Frame(notebook, style="Card.TFrame", padding=20)
        notebook.add(filter_tab, text="Filter")
        notebook.add(analyze_tab, text="Analyze Paths")

        self._build_filter_tab(filter_tab)
        self._build_analyze_tab(analyze_tab)

        log_card = ttk.Frame(wrapper, style="Card.TFrame", padding=20)
        log_card.pack(fill="both", expand=True, pady=(18, 0))
        ttk.Label(log_card, text="Result Log", style="Body.TLabel").pack(anchor="w")

        self.log_box = ScrolledText(
            log_card,
            height=18,
            wrap="word",
            font=("Consolas", 10),
            bg="#fffdf8",
            fg="#1f2933",
            relief="flat",
            padx=12,
            pady=12,
        )
        self.log_box.pack(fill="both", expand=True, pady=(10, 0))
        self.log_box.insert(
            "end",
            "Tab Filter: tao targets/<ip>.txt.\nTab Analyze Paths: path co query thi chi tra element khac nhau, path thuong thi chi tra form/input va full attribute.\n",
        )
        self.log_box.configure(state="disabled")

        footer = ttk.Frame(wrapper, style="App.TFrame")
        footer.pack(fill="x", pady=(12, 0))
        ttk.Label(footer, textvariable=self.status_var, style="Status.TLabel").pack(anchor="w")

    def _build_filter_tab(self, parent: ttk.Frame) -> None:
        self._build_path_row(parent, "Input TXT", self.filter_input_var, self.pick_filter_input_file, 0)
        self._build_path_row(parent, "Input Target", self.filter_target_var, self.pick_filter_target_file, 1)
        self._build_path_row(parent, "Output Folder", self.filter_output_var, self.pick_filter_output_folder, 2)

        button_bar = ttk.Frame(parent, style="Card.TFrame")
        button_bar.grid(row=3, column=0, columnspan=3, sticky="w", pady=(18, 12))

        self.filter_button = ttk.Button(
            button_bar,
            text="Run Filter",
            style="Accent.TButton",
            command=self.start_filter,
        )
        self.filter_button.pack(side="left")

        ttk.Button(
            button_bar,
            text="Open Output",
            style="Secondary.TButton",
            command=self.open_filter_output_folder,
        ).pack(side="left", padx=(10, 0))

        ttk.Button(
            button_bar,
            text="Fill Sample",
            style="Secondary.TButton",
            command=self.fill_filter_sample,
        ).pack(side="left", padx=(10, 0))

        ttk.Label(
            parent,
            text="Output cua tab nay la targets/<ip>.txt. Query trong path se duoc giu lai de tab 2 su dung.",
            style="Body.TLabel",
        ).grid(row=4, column=0, columnspan=3, sticky="w", pady=(6, 0))

    def _build_analyze_tab(self, parent: ttk.Frame) -> None:
        self._build_path_row(parent, "Target File", self.analyze_target_file_var, self.pick_analyze_target_file, 0)
        self._build_path_row(parent, "Base URL", self.analyze_base_url_var, None, 1)
        self._build_path_row(parent, "Login URL", self.analyze_login_url_var, None, 2)
        self._build_path_row(parent, "Username", self.analyze_username_var, None, 3)
        self._build_path_row(parent, "Password", self.analyze_password_var, None, 4, mask=True)
        self._build_path_row(parent, "Output Folder", self.analyze_output_var, self.pick_analyze_output_folder, 5)

        button_bar = ttk.Frame(parent, style="Card.TFrame")
        button_bar.grid(row=6, column=0, columnspan=3, sticky="w", pady=(18, 12))

        self.analyze_button = ttk.Button(
            button_bar,
            text="Analyze Paths",
            style="Accent.TButton",
            command=self.start_analyze,
        )
        self.analyze_button.pack(side="left")

        ttk.Button(
            button_bar,
            text="Open Output",
            style="Secondary.TButton",
            command=self.open_analyze_output_folder,
        ).pack(side="left", padx=(10, 0))

        ttk.Button(
            button_bar,
            text="Fill Sample",
            style="Secondary.TButton",
            command=self.fill_analyze_sample,
        ).pack(side="left", padx=(10, 0))

        ttk.Label(
            parent,
            text="Tool se login truoc bang session cookie. Path co query: chi tra element form/input khac nhau. Path thuong: chi lay form/input va full attribute.",
            style="Body.TLabel",
        ).grid(row=7, column=0, columnspan=3, sticky="w", pady=(6, 0))

    def _build_path_row(
        self,
        parent: ttk.Frame,
        label: str,
        variable: StringVar,
        button_command,
        row: int,
        mask: bool = False,
    ) -> None:
        ttk.Label(parent, text=label, style="Body.TLabel").grid(
            row=row,
            column=0,
            sticky="w",
            pady=(0 if row == 0 else 14, 6),
            padx=(0, 12),
        )
        entry = ttk.Entry(parent, textvariable=variable, width=86, show="*" if mask else "")
        entry.grid(row=row, column=1, sticky="ew", pady=(0 if row == 0 else 14, 6))
        if button_command:
            ttk.Button(parent, text="Browse", style="Secondary.TButton", command=button_command).grid(
                row=row,
                column=2,
                sticky="e",
                pady=(0 if row == 0 else 14, 6),
                padx=(12, 0),
            )
        parent.grid_columnconfigure(1, weight=1)

    def pick_filter_input_file(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Choose TXT file",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
        )
        if file_path:
            self.filter_input_var.set(file_path)

    def pick_filter_target_file(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Choose target TXT file",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
        )
        if file_path:
            self.filter_target_var.set(file_path)

    def pick_filter_output_folder(self) -> None:
        folder_path = filedialog.askdirectory(title="Choose output folder")
        if folder_path:
            self.filter_output_var.set(folder_path)
            self.analyze_output_var.set(folder_path)

    def pick_analyze_target_file(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Choose filtered target file",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
        )
        if file_path:
            self.analyze_target_file_var.set(file_path)

    def pick_analyze_output_folder(self) -> None:
        folder_path = filedialog.askdirectory(title="Choose analysis output folder")
        if folder_path:
            self.analyze_output_var.set(folder_path)

    def fill_filter_sample(self) -> None:
        self.filter_input_var.set(str(Path.cwd() / "sample-input.txt"))
        self.filter_target_var.set(str(Path.cwd() / "sample-targets.txt"))
        self.filter_output_var.set(str(Path.cwd() / "sample-output-python"))
        self.analyze_output_var.set(str(Path.cwd() / "sample-output-python"))
        self.write_log("Sample filter input da duoc dien san.")

    def fill_analyze_sample(self) -> None:
        self.analyze_target_file_var.set(str(Path.cwd() / "sample-analyze-target.txt"))
        self.analyze_base_url_var.set("http://127.0.0.1:8766")
        self.analyze_login_url_var.set("/login")
        self.analyze_username_var.set("admin")
        self.analyze_password_var.set("password")
        self.analyze_output_var.set(str(Path.cwd() / "sample-output-analysis"))
        self.write_log("Sample analyze input da duoc dien san.")

    def write_log(self, message: str) -> None:
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"{message}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def set_running_state(self, running: bool) -> None:
        state = "disabled" if running else "normal"
        self.filter_button.configure(state=state)
        self.analyze_button.configure(state=state)
        self.status_var.set("Processing..." if running else "Ready")

    def start_filter(self) -> None:
        input_value = self.filter_input_var.get().strip()
        target_value = self.filter_target_var.get().strip()
        output_value = self.filter_output_var.get().strip()

        if not input_value:
            messagebox.showwarning("Missing input", "Hay chon file TXT dau vao.")
            return
        if not output_value:
            messagebox.showwarning("Missing output", "Hay chon thu muc output.")
            return

        input_path = Path(input_value)
        output_dir = Path(output_value)
        if not input_path.exists():
            messagebox.showerror("Input error", f"Khong tim thay file:\n{input_path}")
            return

        try:
            target_filters = load_target_filters(target_value)
        except ValueError as exc:
            messagebox.showerror("Target error", str(exc))
            return

        self.set_running_state(True)
        self.write_log(f"Start filter: {input_path}")
        self.write_log(f"Target filter: {', '.join(sorted(target_filters)) if target_filters else 'ALL'}")

        worker = threading.Thread(
            target=self._run_filter,
            args=(input_path, output_dir, target_filters),
            daemon=True,
        )
        worker.start()

    def start_analyze(self) -> None:
        target_file_value = self.analyze_target_file_var.get().strip()
        base_url_value = self.analyze_base_url_var.get().strip()
        login_url_value = self.analyze_login_url_var.get().strip()
        username_value = self.analyze_username_var.get().strip()
        password_value = self.analyze_password_var.get()
        output_value = self.analyze_output_var.get().strip()

        if not target_file_value:
            messagebox.showwarning("Missing target file", "Hay chon file targets/<ip>.txt da loc.")
            return
        if not base_url_value:
            messagebox.showwarning("Missing base URL", "Hay nhap Base URL. Vi du: http://192.168.144.155:3000")
            return
        if not output_value:
            messagebox.showwarning("Missing output", "Hay chon thu muc output.")
            return

        target_file = Path(target_file_value)
        if not target_file.exists():
            messagebox.showerror("Target file error", f"Khong tim thay file:\n{target_file}")
            return

        self.set_running_state(True)
        self.write_log(f"Start analyze: {target_file}")
        self.write_log(f"Base URL: {base_url_value}")
        if username_value and password_value:
            self.write_log(f"Login user: {username_value}")

        worker = threading.Thread(
            target=self._run_analyze,
            args=(target_file, base_url_value, login_url_value, username_value, password_value, Path(output_value)),
            daemon=True,
        )
        worker.start()

    def _run_filter(
        self,
        input_path: Path,
        output_dir: Path,
        target_filters: set[str] | None,
    ) -> None:
        try:
            summary = parse_txt_file(input_path, output_dir, target_filters)
            self.root.after(0, lambda: self._on_filter_success(summary))
        except Exception as exc:  # noqa: BLE001
            self.root.after(0, lambda: self._on_error(exc))

    def _run_analyze(
        self,
        target_file: Path,
        base_url: str,
        login_url: str,
        username: str,
        password: str,
        output_dir: Path,
    ) -> None:
        try:
            summary = analyze_target_paths(
                target_file,
                base_url,
                output_dir,
                login_url=login_url,
                username=username,
                password=password,
            )
            self.root.after(0, lambda: self._on_analyze_success(summary))
        except Exception as exc:  # noqa: BLE001
            self.root.after(0, lambda: self._on_error(exc))

    def _on_filter_success(self, summary: dict[str, object]) -> None:
        self.set_running_state(False)
        self.write_log(f"Done. Parsed {summary['lines']} lines.")
        self.write_log(f"Target filter: {summary['target_filter']}")
        self.write_log(f"Targets kept: {summary['kept']}")
        self.write_log(f"Unique IPs: {summary['unique_ips']}")
        self.write_log(f"Query paths kept: {summary['query_paths_kept']}")
        self.write_log(f"Plain paths kept: {summary['plain_paths_kept']}")
        self.write_log(f"CSS skipped: {summary['css_skipped']}")
        self.write_log(f"Duplicates skipped: {summary['duplicates_skipped']}")
        self.write_log(f"Filter skipped: {summary['filter_skipped']}")
        self.write_log(f"Media found: {summary['media_found']}")
        self.write_log(f"Unparsable lines: {summary['unparsable_lines']}")
        self.write_log(f"Output folder: {summary['output_dir']}")

        target_files = summary.get("target_files", [])
        if target_files:
            self.analyze_target_file_var.set(str(target_files[0]))
            self.analyze_output_var.set(str(summary["output_dir"]))

        messagebox.showinfo("Completed", f"Loc xong.\nOutput: {summary['output_dir']}")

    def _on_analyze_success(self, summary: dict[str, object]) -> None:
        self.set_running_state(False)
        self.write_log(f"Analyze target file: {summary['target_file']}")
        self.write_log(f"Base URL: {summary['base_url']}")
        self.write_log(f"Login attempted: {summary['login_attempted']}")
        self.write_log(f"Login success: {summary['login_success']}")
        if summary["login_error"]:
            self.write_log(f"Login error: {summary['login_error']}")
        self.write_log(f"Query paths analyzed: {summary['query_paths']}")
        self.write_log(f"Plain paths analyzed: {summary['plain_paths']}")
        self.write_log(f"Fetch errors: {summary['fetch_errors']}")
        self.write_log(f"JSON output: {summary['output_file']}")
        messagebox.showinfo("Completed", f"Analyze xong.\nJSON: {summary['output_file']}")

    def _on_error(self, exc: Exception) -> None:
        self.set_running_state(False)
        self.write_log(f"Error: {exc}")
        messagebox.showerror("Processing error", str(exc))

    def open_filter_output_folder(self) -> None:
        self._open_folder(self.filter_output_var.get().strip())

    def open_analyze_output_folder(self) -> None:
        self._open_folder(self.analyze_output_var.get().strip())

    def _open_folder(self, folder_value: str) -> None:
        if not folder_value:
            messagebox.showwarning("Missing output", "Chua co thu muc output de mo.")
            return

        output_dir = Path(folder_value)
        output_dir.mkdir(parents=True, exist_ok=True)
        os.startfile(output_dir)  # type: ignore[attr-defined]


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Filter target paths and analyze filtered paths for query diffs or input elements."
    )
    parser.add_argument("--input", "-i", help="Path to the input TXT file for filtering")
    parser.add_argument("--targets", "-t", help="Target IP list or path to a TXT file containing target IPs")
    parser.add_argument("--output", "-o", default="output", help="Path to the output folder")
    parser.add_argument("--analyze-target-file", help="Path to targets/<ip>.txt for analyze step")
    parser.add_argument("--base-url", help="Base URL used to fetch filtered paths, for example http://192.168.144.155:3000")
    parser.add_argument("--login-url", default="", help="Optional login URL or path, for example /login or http://host/login")
    parser.add_argument("--username", default="admin", help="Login username for analyze step")
    parser.add_argument("--password", default="password", help="Login password for analyze step")
    parser.add_argument("--timeout", type=float, default=10.0, help="Timeout in seconds for each page fetch")
    parser.add_argument("--no-ui", action="store_true", help="Run in CLI mode.")
    return parser


def run_cli(
    input_path: str | None,
    output_dir: str,
    target_input: str | None,
    analyze_target_file: str | None,
    base_url: str | None,
    login_url: str,
    username: str,
    password: str,
    timeout_seconds: float,
) -> int:
    if input_path:
        target_filters = load_target_filters(target_input)
        summary = parse_txt_file(Path(input_path), Path(output_dir), target_filters)
        print(f"Done. Parsed {summary['lines']} lines.")
        print(f"Target filter: {summary['target_filter']}")
        print(f"Targets kept: {summary['kept']}")
        print(f"Unique IPs: {summary['unique_ips']}")
        print(f"Query paths kept: {summary['query_paths_kept']}")
        print(f"Plain paths kept: {summary['plain_paths_kept']}")
        print(f"CSS skipped: {summary['css_skipped']}")
        print(f"Duplicates skipped: {summary['duplicates_skipped']}")
        print(f"Filter skipped: {summary['filter_skipped']}")
        print(f"Media found: {summary['media_found']}")
        print(f"Unparsable lines: {summary['unparsable_lines']}")
        print(f"Output folder: {summary['output_dir']}")

    if analyze_target_file:
        if not base_url:
            raise ValueError("Hay truyen --base-url khi dung --analyze-target-file.")
        summary = analyze_target_paths(
            Path(analyze_target_file),
            base_url,
            Path(output_dir),
            login_url=login_url,
            username=username,
            password=password,
            timeout_seconds=timeout_seconds,
        )
        print(f"Analyze target file: {summary['target_file']}")
        print(f"Base URL: {summary['base_url']}")
        print(f"Login attempted: {summary['login_attempted']}")
        print(f"Login success: {summary['login_success']}")
        if summary["login_error"]:
            print(f"Login error: {summary['login_error']}")
        print(f"Query paths analyzed: {summary['query_paths']}")
        print(f"Plain paths analyzed: {summary['plain_paths']}")
        print(f"Fetch errors: {summary['fetch_errors']}")
        print(f"JSON output: {summary['output_file']}")

    return 0


def run_ui() -> int:
    root = Tk()
    TargetFilterApp(root)
    root.mainloop()
    return 0


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.no_ui or args.input or args.analyze_target_file:
        if not args.input and not args.analyze_target_file:
            parser.error("Can co --input hoac --analyze-target-file khi dung CLI mode")
        return run_cli(
            args.input,
            args.output,
            args.targets,
            args.analyze_target_file,
            args.base_url,
            args.login_url,
            args.username,
            args.password,
            args.timeout,
        )

    return run_ui()


if __name__ == "__main__":
    raise SystemExit(main())
