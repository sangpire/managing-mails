# managing-mails

IMAP 기반으로 메일 목록 조회, 본문 읽기, UID 삭제를 수행하는 Codex 스킬입니다.

이 스킬은 `GPT-5.3-Codex`를 이용해 작성되었습니다.

- 이 Skill 은 개인적으로 사용하기 위해 만든 것입니다.
- 누구나 가져가 수정&사용 하셔도 됩니다.

## 개요

이 저장소는 `scripts/imap_read.py`를 중심으로 다음 작업을 제공합니다.

- 메일 목록 조회 (`--mode list`)
- 특정 UID 본문 조회 (`--mode read`)
- 특정 UID 삭제 (`--mode delete`)
- RFC 2047 헤더 디코딩
- 본문 요약/URL/장애 필드 추출 (`parsed_body`)

## 구성 파일

설정 파일 경로는 아래 둘 중 하나로 지정합니다.

- `--config <path>`
- `MANAGING_MAIL_CONFIG_PATH=<path>`

권장 저장 위치 예시: `~/.config/managing-mails/mails.toml`

### 설정 예시

```toml
version = 1
default_account = "work"

[[accounts]]
name = "work"
host = "imap.example.com"
port = 993
ssl = true
username = "user@example.com"
password = "app-password-or-imap-password"
mailbox = "INBOX"
default_since_days = 7
```

### 권한 설정(Unix/macOS)

```bash
mkdir -p ~/.config/managing-mails
cp mails.example.toml ~/.config/managing-mails/mails.toml
chmod 700 ~/.config/managing-mails
chmod 600 ~/.config/managing-mails/mails.toml
```

권한이 맞지 않으면 `CONFIG_PERMISSION_DENIED` 오류가 발생합니다.

## 요구사항

- Python 3.11 이상 (`tomllib` 사용)
- IMAP 접근 가능한 계정
- 앱 비밀번호(제공자 정책에 따라 필요)

## 실행 방법

저장소 루트에서 실행하는 예시입니다.

```bash
export MANAGING_MAIL_CONFIG_PATH=~/.config/managing-mails/mails.toml
```

### 1) 목록 조회

```bash
python3 scripts/imap_read.py --mode list
```

### 2) 본문 조회

```bash
python3 scripts/imap_read.py --mode read --uid 12345
```

### 3) 삭제

```bash
python3 scripts/imap_read.py --mode delete --uid 12345
```

### 4) 주요 옵션

- `--account <name>`: 계정 선택
- `--mailbox <name>`: 메일함 선택
- `--since YYYY-MM-DD`: 조회 시작일
- `--limit N`: 목록 개수 (기본 20)
- `--query '<IMAP SEARCH TOKENS>'`: 검색 조건
- `--include-html`: `read` 결과에 `html_body` 포함
- `--no-expunge`: `delete` 시 즉시 영구삭제 없이 `\Deleted`만 설정
- `--config <path>`: 설정 파일 경로 지정 (최우선)
- `MANAGING_MAIL_CONFIG_PATH`: `--config` 미지정 시 사용할 설정 파일 경로

예시:

```bash
python3 scripts/imap_read.py --mode list --since 2026-02-01 --query 'FROM "boss@example.com" SUBJECT "urgent"'
```

## 출력 형식

모든 결과는 JSON입니다.

- `list`: `messages[]` (uid/date/from/subject/flags)
- `read`: `message` (headers/text_body/parsed_body/attachments/flags)
- `delete`: `result` (deleted_flag_set/expunged/remaining_matches)

`parsed_body`에는 다음이 포함됩니다.

- `source`
- `summary`
- `incident_fields`
- `urls`

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

## Codex Skill 메타데이터

- 스킬 설명: `SKILL.md`
- 인터페이스 메타: `agents/openai.yaml`
- 참고 문서:
  - `references/search-recipes.md`
  - `references/provider-quirks.md`

## 외부 공유 체크리스트

- 실제 계정 비밀번호는 로컬 설정 파일(`~/.config/managing-mails/mails.toml` 등)에만 두고, 공유 시에는 `mails.example.toml`만 제공
- 폴더 압축 공유 시 `.git/` 폴더 제외 (작성자 이름/이메일 등 로컬 Git 메타데이터 노출 방지)

## License

MIT License를 따릅니다. 자세한 내용은 `LICENSE` 파일을 참고하세요.
