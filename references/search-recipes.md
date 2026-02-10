# IMAP 검색 레시피

`--query`는 IMAP SEARCH 토큰을 그대로 전달합니다. 공백/따옴표 처리를 위해 전체를 문자열로 감싸세요.

## 예시

### 발신자 기준

```bash
python3 scripts/imap_read.py \
  --mode list \
  --query 'FROM "sender@example.com"'
```

### 제목 기준

```bash
python3 scripts/imap_read.py \
  --mode list \
  --query 'SUBJECT "회의"'
```

### 미읽음 메일

```bash
python3 scripts/imap_read.py \
  --mode list \
  --query 'UNSEEN'
```

### 특정 기간 + 조건

```bash
python3 scripts/imap_read.py \
  --mode list \
  --since 2026-02-01 \
  --query 'FROM "boss@example.com" SUBJECT "urgent"'
```
