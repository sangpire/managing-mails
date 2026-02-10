#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import email
import imaplib
import json
import os
import re
import shlex
import stat
import sys
import tomllib
from dataclasses import dataclass
from email.header import decode_header
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

def resolve_default_config_path() -> Path:
    codex_home = os.environ.get("CODEX_HOME")
    default_base = Path(codex_home).expanduser() if codex_home else Path.home() / ".codex"
    candidates = [
        default_base / ".secrets" / "mails.toml",
        Path.home() / ".codex" / ".secrets" / "mails.toml",
        Path.cwd() / ".secrets" / "mails.toml",
    ]
    for path in candidates:
        if path.exists():
            return path
    return candidates[0]


DEFAULT_CONFIG_PATH = resolve_default_config_path()
IMAP_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
BLOCK_TAGS = {
    "address",
    "article",
    "aside",
    "blockquote",
    "br",
    "caption",
    "div",
    "dl",
    "dt",
    "dd",
    "fieldset",
    "figcaption",
    "figure",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "li",
    "main",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "td",
    "th",
    "tr",
    "ul",
}
SUMMARY_NOISE_PATTERNS = (
    re.compile(r"^\s*$"),
    re.compile(r"^message title$", re.IGNORECASE),
    re.compile(r"^go to page history$", re.IGNORECASE),
    re.compile(r"^view page$", re.IGNORECASE),
    re.compile(r"^manage notifications$", re.IGNORECASE),
    re.compile(r"^stop watching space$", re.IGNORECASE),
    re.compile(r"^there('?s| is)\s+\d+\s+new edit", re.IGNORECASE),
    re.compile(r"^this message was sent by atlassian confluence", re.IGNORECASE),
)
INCIDENT_FIELD_ALIASES = {
    "작성자": ("작성자",),
    "작성일시": ("작성일시",),
    "서비스명": ("서비스명", "그룹명/서비스명"),
    "작업 서버": ("작업 서버",),
    "장애 원인": ("장애 원인",),
    "처리자": ("처리자",),
    "서비스 담당자": ("서비스 담당자",),
    "장애 티켓": ("장애 티켓", "티켓"),
}


class SkillError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class AccountConfig:
    name: str
    host: str
    port: int
    ssl: bool
    username: str
    password: str
    mailbox: str
    default_since_days: int


class HTMLTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._skip_depth = 0
        self._parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lowered = tag.lower()
        if lowered in ("script", "style"):
            self._skip_depth += 1
            return
        if lowered in BLOCK_TAGS:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
        if lowered in ("script", "style"):
            if self._skip_depth > 0:
                self._skip_depth -= 1
            return
        if lowered in BLOCK_TAGS:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0:
            self._parts.append(data)

    def text(self) -> str:
        return "".join(self._parts)


def emit_json(payload: dict[str, Any], *, exit_code: int = 0, error: bool = False) -> None:
    stream = sys.stderr if error else sys.stdout
    stream.write(json.dumps(payload, ensure_ascii=False, indent=2))
    stream.write("\n")
    raise SystemExit(exit_code)


def fail(code: str, message: str) -> None:
    emit_json({"ok": False, "error": {"code": code, "message": message}}, exit_code=1, error=True)


def decode_header_value(raw_value: str | None) -> str:
    if raw_value is None:
        return ""
    decoded_parts: list[str] = []
    for value, enc in decode_header(raw_value):
        if isinstance(value, bytes):
            charset = enc or "utf-8"
            decoded_parts.append(value.decode(charset, errors="replace"))
        else:
            decoded_parts.append(value)
    return "".join(decoded_parts).strip()


def decode_payload(payload: bytes | None, charset: str | None) -> str:
    if not payload:
        return ""
    if charset:
        try:
            return payload.decode(charset, errors="replace")
        except LookupError:
            pass
    for fallback in ("utf-8", "cp949", "iso-8859-1"):
        try:
            return payload.decode(fallback, errors="replace")
        except LookupError:
            continue
    return payload.decode(errors="replace")


def extract_urls(raw_text: str) -> list[str]:
    urls = re.findall(r"https?://[^\s\"'<>]+", raw_text)
    unique_urls: list[str] = []
    seen: set[str] = set()
    for url in urls:
        cleaned = unescape(url).rstrip(".,;)")
        if cleaned not in seen:
            unique_urls.append(cleaned)
            seen.add(cleaned)
    return unique_urls


def html_to_text(html_body: str) -> str:
    parser = HTMLTextParser()
    parser.feed(html_body)
    parser.close()
    text = unescape(parser.text()).replace("\r", "\n")
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip()


def normalize_lines(text: str) -> list[str]:
    normalized = text.replace("\r", "\n")
    lines = [line.strip() for line in normalized.split("\n")]
    cleaned: list[str] = []
    for line in lines:
        if not line:
            continue
        compact = re.sub(r"\s+", " ", line)
        if any(pattern.search(compact) for pattern in SUMMARY_NOISE_PATTERNS):
            continue
        cleaned.append(compact)
    return cleaned


def build_summary(lines: list[str], *, max_lines: int = 25, max_chars: int = 1800) -> str:
    picked: list[str] = []
    total = 0
    for line in lines:
        if total + len(line) > max_chars:
            break
        picked.append(line)
        total += len(line)
        if len(picked) >= max_lines:
            break
    return "\n".join(picked)


def extract_incident_fields(lines: list[str]) -> dict[str, str]:
    alias_to_key: dict[str, str] = {}
    for canonical_key, aliases in INCIDENT_FIELD_ALIASES.items():
        alias_to_key[canonical_key] = canonical_key
        for alias in aliases:
            alias_to_key[alias] = canonical_key

    def extract_inline(line: str) -> tuple[str, str] | None:
        for alias in sorted(alias_to_key.keys(), key=len, reverse=True):
            if line.startswith(alias):
                value = line[len(alias) :].lstrip(": \t")
                if value:
                    return alias_to_key[alias], value
        return None

    fields: dict[str, str] = {}
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        inline = extract_inline(line)
        if inline:
            key, value = inline
            if key not in fields and value:
                fields[key] = value
            idx += 1
            continue

        line_key = alias_to_key.get(line)
        if not line_key:
            idx += 1
            continue

        key_block: list[str] = []
        block_idx = idx
        while block_idx < len(lines):
            key = alias_to_key.get(lines[block_idx])
            if not key:
                break
            if key not in key_block and key not in fields:
                key_block.append(key)
            block_idx += 1

        if not key_block:
            idx += 1
            continue

        value_block: list[str] = []
        value_idx = block_idx
        while value_idx < len(lines) and len(value_block) < len(key_block):
            if alias_to_key.get(lines[value_idx]):
                break
            value_block.append(lines[value_idx])
            value_idx += 1

        for key, value in zip(key_block, value_block):
            if key not in fields and value:
                fields[key] = value

        idx = value_idx

    return fields


def build_parsed_body(text_body: str, html_body: str, body_source: str) -> dict[str, Any]:
    normalized_text = text_body.strip()
    if not normalized_text and html_body:
        normalized_text = html_to_text(html_body)

    lines = normalize_lines(normalized_text)
    summary = build_summary(lines)
    urls = extract_urls(html_body or normalized_text)
    incident_fields = extract_incident_fields(lines)
    return {
        "source": body_source,
        "summary": summary,
        "incident_fields": incident_fields,
        "urls": urls[:20],
    }


def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read and delete emails via IMAP using TOML file configuration.")
    parser.add_argument("--mode", choices=("list", "read", "delete"), required=True)
    parser.add_argument("--account")
    parser.add_argument("--mailbox")
    parser.add_argument("--since", help="Format: YYYY-MM-DD")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--uid")
    parser.add_argument("--query")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    parser.add_argument("--include-html", action="store_true")
    parser.add_argument(
        "--no-expunge",
        action="store_true",
        help="delete 모드에서 즉시 영구 삭제(EXPUNGE)하지 않고 \\Deleted 플래그만 설정",
    )
    return parser.parse_args()


def ensure_secure_permissions(config_path: Path) -> None:
    if not config_path.exists():
        raise SkillError("CONFIG_NOT_FOUND", f"설정 파일이 없습니다: {config_path}")

    if not config_path.is_file():
        raise SkillError("CONFIG_SCHEMA_ERROR", f"설정 경로가 파일이 아닙니다: {config_path}")

    secrets_dir = config_path.parent
    if not secrets_dir.exists():
        raise SkillError("CONFIG_NOT_FOUND", f"설정 디렉터리가 없습니다: {secrets_dir}")

    if sys.platform != "win32":
        dir_mode = stat.S_IMODE(secrets_dir.stat().st_mode)
        if dir_mode != 0o700:
            raise SkillError(
                "CONFIG_PERMISSION_DENIED",
                f"설정 디렉터리 권한이 700이 아닙니다: {secrets_dir} ({oct(dir_mode)})",
            )
        file_mode = stat.S_IMODE(config_path.stat().st_mode)
        if file_mode != 0o600:
            raise SkillError(
                "CONFIG_PERMISSION_DENIED",
                f"설정 파일 권한이 600이 아닙니다: {config_path} ({oct(file_mode)})",
            )


def validate_account(raw: dict[str, Any], index: int) -> AccountConfig:
    required_fields = ("name", "host", "username", "password")
    for key in required_fields:
        value = raw.get(key)
        if not isinstance(value, str) or not value.strip():
            raise SkillError("CONFIG_SCHEMA_ERROR", f"accounts[{index}].{key}가 비어있거나 문자열이 아닙니다.")

    port = raw.get("port", 993)
    if not isinstance(port, int) or port <= 0:
        raise SkillError("CONFIG_SCHEMA_ERROR", f"accounts[{index}].port는 양의 정수여야 합니다.")

    ssl = raw.get("ssl", True)
    if not isinstance(ssl, bool):
        raise SkillError("CONFIG_SCHEMA_ERROR", f"accounts[{index}].ssl은 bool이어야 합니다.")

    mailbox = raw.get("mailbox", "INBOX")
    if not isinstance(mailbox, str) or not mailbox.strip():
        raise SkillError("CONFIG_SCHEMA_ERROR", f"accounts[{index}].mailbox가 비어있거나 문자열이 아닙니다.")

    default_since_days = raw.get("default_since_days", 7)
    if not isinstance(default_since_days, int) or default_since_days < 0:
        raise SkillError("CONFIG_SCHEMA_ERROR", f"accounts[{index}].default_since_days는 0 이상의 정수여야 합니다.")

    return AccountConfig(
        name=raw["name"].strip(),
        host=raw["host"].strip(),
        port=port,
        ssl=ssl,
        username=raw["username"].strip(),
        password=raw["password"],
        mailbox=mailbox.strip(),
        default_since_days=default_since_days,
    )


def load_config(config_path: Path) -> tuple[str, dict[str, AccountConfig]]:
    ensure_secure_permissions(config_path)

    try:
        raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise SkillError("CONFIG_PARSE_ERROR", f"TOML 파싱 실패: {exc}") from exc
    except OSError as exc:
        raise SkillError("CONFIG_NOT_FOUND", f"설정 파일을 읽을 수 없습니다: {exc}") from exc

    version = raw.get("version", 1)
    if not isinstance(version, int):
        raise SkillError("CONFIG_SCHEMA_ERROR", "version은 정수여야 합니다.")

    default_account = raw.get("default_account")
    if not isinstance(default_account, str) or not default_account.strip():
        raise SkillError("CONFIG_SCHEMA_ERROR", "default_account는 비어있지 않은 문자열이어야 합니다.")

    accounts_raw = raw.get("accounts")
    if not isinstance(accounts_raw, list) or not accounts_raw:
        raise SkillError("CONFIG_SCHEMA_ERROR", "accounts는 최소 1개 이상의 배열이어야 합니다.")

    accounts: dict[str, AccountConfig] = {}
    for idx, item in enumerate(accounts_raw):
        if not isinstance(item, dict):
            raise SkillError("CONFIG_SCHEMA_ERROR", f"accounts[{idx}]는 객체여야 합니다.")
        account = validate_account(item, idx)
        if account.name in accounts:
            raise SkillError("CONFIG_SCHEMA_ERROR", f"중복 account name: {account.name}")
        accounts[account.name] = account

    if default_account not in accounts:
        raise SkillError("ACCOUNT_NOT_FOUND", f"default_account '{default_account}'를 찾을 수 없습니다.")

    return default_account, accounts


def parse_since_date(raw_since: str | None, default_since_days: int) -> dt.date:
    if raw_since:
        try:
            return dt.datetime.strptime(raw_since, "%Y-%m-%d").date()
        except ValueError as exc:
            raise SkillError("CONFIG_SCHEMA_ERROR", "--since 형식은 YYYY-MM-DD 이어야 합니다.") from exc
    return dt.date.today() - dt.timedelta(days=default_since_days)


def build_search_criteria(since_date: dt.date, raw_query: str | None) -> list[str]:
    criteria: list[str] = ["SINCE", f"{since_date.day:02d}-{IMAP_MONTHS[since_date.month - 1]}-{since_date.year}"]
    if raw_query:
        try:
            query_tokens = shlex.split(raw_query)
        except ValueError as exc:
            raise SkillError("CONFIG_SCHEMA_ERROR", f"--query 파싱 실패: {exc}") from exc
        if query_tokens:
            criteria.extend(query_tokens)
    return criteria


def connect_imap(account: AccountConfig) -> imaplib.IMAP4:
    try:
        client = imaplib.IMAP4_SSL(account.host, account.port) if account.ssl else imaplib.IMAP4(account.host, account.port)
    except Exception as exc:
        raise SkillError("IMAP_CONNECT_ERROR", f"IMAP 서버 연결 실패: {account.host}:{account.port}") from exc

    try:
        client.login(account.username, account.password)
    except imaplib.IMAP4.error as exc:
        try:
            client.logout()
        except Exception:
            pass
        raise SkillError("AUTH_FAILED", "IMAP 인증에 실패했습니다. 아이디/비밀번호를 확인하세요.") from exc
    return client


def select_mailbox(client: imaplib.IMAP4, mailbox: str, *, readonly: bool = True) -> None:
    try:
        status, _ = client.select(mailbox, readonly=readonly)
    except imaplib.IMAP4.error as exc:
        raise SkillError("MAILBOX_NOT_FOUND", f"메일함 선택 실패: {mailbox}") from exc
    if status != "OK":
        raise SkillError("MAILBOX_NOT_FOUND", f"메일함 선택 실패: {mailbox}")


def parse_flags(fetch_meta: bytes) -> list[str]:
    match = re.search(rb"FLAGS \(([^)]*)\)", fetch_meta)
    if not match:
        return []
    raw = match.group(1).decode("ascii", errors="ignore").strip()
    return [token for token in raw.split() if token]


def collect_fetch_payload(fetch_data: list[Any]) -> tuple[bytes, bytes]:
    message_bytes = b""
    fetch_meta = b""
    for item in fetch_data:
        if isinstance(item, tuple):
            if isinstance(item[0], bytes):
                fetch_meta = item[0]
            if len(item) > 1 and isinstance(item[1], bytes):
                message_bytes += item[1]
    return fetch_meta, message_bytes


def list_messages(client: imaplib.IMAP4, since_date: dt.date, query: str | None, limit: int) -> list[dict[str, Any]]:
    if limit <= 0:
        raise SkillError("CONFIG_SCHEMA_ERROR", "--limit은 1 이상이어야 합니다.")

    criteria = build_search_criteria(since_date, query)
    status, data = client.uid("SEARCH", None, *criteria)
    if status != "OK":
        raise SkillError("IMAP_CONNECT_ERROR", "메일 검색에 실패했습니다.")

    uid_tokens = data[0].split() if data and data[0] else []
    selected = uid_tokens[-limit:]
    selected.reverse()
    messages: list[dict[str, Any]] = []

    for uid_token in selected:
        uid = uid_token.decode("ascii", errors="ignore")
        fetch_status, fetch_data = client.uid("FETCH", uid, "(UID FLAGS BODY.PEEK[HEADER.FIELDS (DATE FROM SUBJECT)])")
        if fetch_status != "OK" or not isinstance(fetch_data, list):
            continue
        fetch_meta, header_bytes = collect_fetch_payload(fetch_data)
        parsed = email.message_from_bytes(header_bytes)
        messages.append(
            {
                "uid": uid,
                "date": decode_header_value(parsed.get("Date")),
                "from": decode_header_value(parsed.get("From")),
                "subject": decode_header_value(parsed.get("Subject")),
                "flags": parse_flags(fetch_meta),
            }
        )

    return messages


def find_uid_matches(client: imaplib.IMAP4, uid: str) -> list[str]:
    status, data = client.uid("SEARCH", None, "UID", uid)
    if status != "OK":
        raise SkillError("IMAP_CONNECT_ERROR", "UID 검색에 실패했습니다.")
    if not data or not data[0]:
        return []
    return data[0].decode("ascii", errors="ignore").split()


def delete_message(client: imaplib.IMAP4, uid: str, *, expunge: bool) -> dict[str, Any]:
    before_matches = find_uid_matches(client, uid)
    if uid not in before_matches:
        raise SkillError("MESSAGE_NOT_FOUND", f"UID {uid} 메일을 찾을 수 없습니다.")

    store_status, store_data = client.uid("STORE", uid, "+FLAGS.SILENT", "(\\Deleted)")
    if store_status != "OK":
        raise SkillError("DELETE_FAILED", f"UID {uid} 삭제 플래그 설정 실패: {store_data}")

    flags_status, flags_data = client.uid("FETCH", uid, "(FLAGS)")
    deleted_flag_set = False
    if flags_status == "OK" and isinstance(flags_data, list):
        fetch_meta, _ = collect_fetch_payload(flags_data)
        deleted_flag_set = "\\Deleted" in parse_flags(fetch_meta)

    expunged = False
    if expunge:
        expunge_status, expunge_data = client.expunge()
        if expunge_status != "OK":
            raise SkillError("DELETE_FAILED", f"EXPUNGE 실패: {expunge_data}")
        after_matches = find_uid_matches(client, uid)
        expunged = uid not in after_matches
    else:
        after_matches = find_uid_matches(client, uid)

    return {
        "uid": uid,
        "deleted_flag_set": deleted_flag_set,
        "expunged": expunged,
        "remaining_matches": after_matches,
    }


def read_message(client: imaplib.IMAP4, uid: str, include_html: bool) -> dict[str, Any]:
    fetch_status, fetch_data = client.uid("FETCH", uid, "(UID FLAGS BODY.PEEK[])")
    if fetch_status != "OK" or not isinstance(fetch_data, list):
        raise SkillError("IMAP_CONNECT_ERROR", f"UID {uid} 메일 조회에 실패했습니다.")

    fetch_meta, message_bytes = collect_fetch_payload(fetch_data)
    if not message_bytes:
        raise SkillError("IMAP_CONNECT_ERROR", f"UID {uid} 메일 본문이 비어있습니다.")

    parsed = email.message_from_bytes(message_bytes)
    headers = {
        "date": decode_header_value(parsed.get("Date")),
        "from": decode_header_value(parsed.get("From")),
        "to": decode_header_value(parsed.get("To")),
        "subject": decode_header_value(parsed.get("Subject")),
        "message_id": decode_header_value(parsed.get("Message-ID")),
    }

    text_body = ""
    html_body = ""
    body_source = "text/plain"
    attachments: list[dict[str, Any]] = []

    if parsed.is_multipart():
        for part in parsed.walk():
            if part.is_multipart():
                continue
            content_type = part.get_content_type().lower()
            disposition = (part.get("Content-Disposition") or "").lower()
            filename = decode_header_value(part.get_filename())
            payload = part.get_payload(decode=True)

            if "attachment" in disposition or filename:
                attachments.append(
                    {
                        "filename": filename,
                        "content_type": content_type,
                        "size": len(payload or b""),
                    }
                )
                continue

            charset = part.get_content_charset()
            if content_type == "text/plain" and not text_body:
                text_body = decode_payload(payload, charset)
                body_source = "text/plain"
            elif content_type == "text/html" and not html_body:
                html_body = decode_payload(payload, charset)
    else:
        payload = parsed.get_payload(decode=True)
        charset = parsed.get_content_charset()
        content_type = parsed.get_content_type().lower()
        if content_type == "text/html":
            html_body = decode_payload(payload, charset)
            body_source = "text/html"
        else:
            text_body = decode_payload(payload, charset)
            body_source = "text/plain"

    if not text_body and html_body:
        text_body = html_to_text(html_body)
        body_source = "text/html"

    parsed_body = build_parsed_body(text_body, html_body, body_source)

    response: dict[str, Any] = {
        "uid": uid,
        "headers": headers,
        "text_body": text_body,
        "parsed_body": parsed_body,
        "attachments": attachments,
        "flags": parse_flags(fetch_meta),
    }
    if include_html and html_body:
        response["html_body"] = html_body
    return response


def resolve_account(
    accounts: dict[str, AccountConfig], default_account: str, requested_account: str | None
) -> AccountConfig:
    selected_name = requested_account or default_account
    account = accounts.get(selected_name)
    if account is None:
        raise SkillError("ACCOUNT_NOT_FOUND", f"account '{selected_name}'를 찾을 수 없습니다.")
    return account


def main() -> None:
    args = parse_cli_args()
    config_path = Path(args.config).expanduser()

    if args.mode in ("read", "delete") and not args.uid:
        fail("CONFIG_SCHEMA_ERROR", f"--mode {args.mode} 에서는 --uid가 필요합니다.")

    try:
        default_account, accounts = load_config(config_path)
        account = resolve_account(accounts, default_account, args.account)
        mailbox = (args.mailbox or account.mailbox).strip()
        client = connect_imap(account)
        try:
            if args.mode == "list":
                since_date = parse_since_date(args.since, account.default_since_days)
                select_mailbox(client, mailbox, readonly=True)
                messages = list_messages(client, since_date, args.query, args.limit)
                emit_json(
                    {
                        "ok": True,
                        "mode": "list",
                        "account": account.name,
                        "mailbox": mailbox,
                        "since": since_date.isoformat(),
                        "count": len(messages),
                        "messages": messages,
                    }
                )
            elif args.mode == "read":
                select_mailbox(client, mailbox, readonly=True)
                message = read_message(client, args.uid, args.include_html)
                emit_json(
                    {
                        "ok": True,
                        "mode": "read",
                        "account": account.name,
                        "mailbox": mailbox,
                        "message": message,
                    }
                )
            else:
                select_mailbox(client, mailbox, readonly=False)
                result = delete_message(client, args.uid, expunge=not args.no_expunge)
                emit_json(
                    {
                        "ok": True,
                        "mode": "delete",
                        "account": account.name,
                        "mailbox": mailbox,
                        "result": result,
                    }
                )
        finally:
            try:
                client.logout()
            except Exception:
                pass
    except SkillError as exc:
        fail(exc.code, exc.message)


if __name__ == "__main__":
    main()
