---
name: managing-mails
description: IMAP 프로토콜로 메일함 목록 조회, 본문 읽기, UID 기반 삭제를 수행합니다. 메일 검색, RFC 2047 헤더 디코딩, 파일 기반 설정(`.secrets/mails.toml`)으로 메일을 관리해야 할 때 사용하세요.
allowed-tools: Bash(python3:*), Read, Write
---

# IMAP 메일 관리 스킬

IMAP 계정 정보를 파일로 로드하여 메일 목록 조회, 본문 읽기, 삭제를 처리합니다.

## 빠른 시작

1. 설정 파일 준비

```bash
mkdir -p .secrets
cp mails.example.toml .secrets/mails.toml
chmod 700 .secrets
chmod 600 .secrets/mails.toml
```

2. 메일 목록 확인

```bash
python3 scripts/imap_read.py --mode list
```

3. 특정 UID 본문 읽기

```bash
python3 scripts/imap_read.py --mode read --uid 12345
```

4. 특정 UID 메일 삭제

```bash
python3 scripts/imap_read.py --mode delete --uid 12345
```

## CLI 인터페이스

- `--mode list|read|delete` (필수)
- `--account <name>` (선택, 미지정 시 `default_account`)
- `--mailbox <name>` (선택, 미지정 시 계정 기본값)
- `--since YYYY-MM-DD` (선택, 미지정 시 계정별 `default_since_days`)
- `--limit N` (기본 20)
- `--uid <uid>` (`mode=read|delete` 필수)
- `--query "<search expr>"` (선택)
- `--config <path>` (선택, 기본 `$CODEX_HOME/.secrets/mails.toml` 또는 `~/.codex/.secrets/mails.toml` 또는 `./.secrets/mails.toml`)
- `--include-html` (`mode=read`에서 HTML 본문 포함)
- `--no-expunge` (`mode=delete`에서 즉시 영구삭제 없이 `\Deleted` 플래그만 설정)

## 출력 형식

- `list`: `[{uid, date, from, subject, flags}]`
- `read`: `{uid, headers, text_body, parsed_body, html_body?, attachments[]}`
- `delete`: `{uid, deleted_flag_set, expunged, remaining_matches[]}`

`parsed_body`는 사람이 읽기 쉬운 본문 파싱 결과를 제공합니다.

- `source`: 파싱 원본(`text/plain` 또는 `text/html`)
- `summary`: 주요 본문 요약(줄바꿈 유지)
- `incident_fields`: 장애 문서에서 추출한 핵심 필드(작성자/서비스명/장애 원인/티켓 등)
- `urls`: 본문에서 추출한 링크 목록

## 에러 코드

- `CONFIG_NOT_FOUND`
- `CONFIG_PARSE_ERROR`
- `CONFIG_SCHEMA_ERROR`
- `CONFIG_PERMISSION_DENIED`
- `ACCOUNT_NOT_FOUND`
- `IMAP_CONNECT_ERROR`
- `AUTH_FAILED`
- `MAILBOX_NOT_FOUND`
- `MESSAGE_NOT_FOUND`
- `DELETE_FAILED`

세부 동작은 아래 참조 문서를 따릅니다.

- 제공자 특이사항: `references/provider-quirks.md`
- 검색 레시피: `references/search-recipes.md`
