# security-check-mcp

비개발자도 사용할 수 있도록 만든 보안 점검용 MCP 서버입니다.

이 프로젝트의 목표는 바이브 코딩, 노코드, 로우코드에 가깝게 만든 서비스를 대상으로 보안 문제를 빠르게 점검하고, 이해하기 쉬운 리포트를 제공하는 것입니다.

리포트는 아래에 집중합니다.

- 어떤 문제가 있는지
- 그 문제가 왜 위험한지
- 공격자가 어떻게 악용할 수 있는지
- 지금 출시해도 되는지

## 한 줄 설명

코드, 실제 배포 응답, 공개 공격 표면, 로그인 후 권한 문제를 함께 점검하는 보안 점검 MCP입니다.

## 무엇을 점검하나

1. 코드 정적 점검
2. 배포된 서비스의 실제 응답 점검
3. 공격자가 먼저 눌러볼 공개 경로 점검
4. 로그인된 일반 사용자 권한으로 관리자/타인 데이터 접근이 되는지 점검

## 대상 사용자

- 개발 지식이 많지 않은 서비스 운영자
- MCP를 통해 자동으로 보안 점검 리포트를 받고 싶은 사람
- 출시 전 "지금 바로 막아야 하는 문제"를 빠르게 확인하고 싶은 팀

## 핵심 특징

- 비개발자도 읽기 쉬운 한국어 리포트
- `출시 차단 / 수정 후 재점검 / 기본 점검 통과` 판정 제공
- 코드, 응답 헤더, 쿠키, 공개 경로, 인증 후 권한 문제까지 함께 점검
- 프레임워크와 무관한 공통 위험 패턴 점검
- Express, Next.js, Django, Flask, FastAPI, Spring, NestJS, Rails, Laravel 등 일부 프레임워크 대표 설정 실수 점검
- 공격자 관점의 위험 설명 포함

## 지원 범위

이 MCP는 모든 프레임워크 프로젝트에 대해 기본적인 공통 보안 패턴을 점검할 수 있습니다.

프레임워크와 무관하게 주로 보는 항목은 아래와 같습니다.

- 코드에 직접 들어간 API 키, 비밀번호, 토큰, DB URL, private key
- SQL Injection, Command Injection, SSRF로 이어질 수 있는 위험 패턴
- `eval`, `exec`, 민감정보 로그, 디버그 설정
- CORS 전체 허용, JWT localStorage 저장, 쿠키 보안 속성 누락 가능성
- `.gitignore`와 `.env` 관리 실수

다만 모든 프레임워크의 보안 설정과 권한 모델을 100% 검증하지는 않습니다.

프레임워크 특화 점검은 현재 Django, Flask, FastAPI, Spring, Next.js, Express/NestJS/Fastify, Rails, Laravel 쪽의 대표적인 설정 실수 위주입니다. 그 외 프레임워크는 공통 패턴 점검 중심으로 동작합니다.

## 제공하는 Tool

### `check_security`

프로젝트 디렉터리를 정적 분석합니다.

주요 점검:

- 하드코딩된 API 키, 비밀번호, 토큰, DB URL
- SQL Injection, Command Injection, SSRF, `eval`, `exec`
- 인증 없는 admin 라우트
- JWT 검증 누락
- 로그 민감정보 노출
- Rate Limit 누락 가능성
- 업로드/경로 탈출 위험
- 디버그 모드, `.gitignore`, 프레임워크별 대표 설정 실수

### `security_check`

정적 점검, OpenAPI 문서 점검, 라이브 점검, 공격 표면 점검, 인증 기반 권한 점검을 한 번에 실행합니다.

주요 입력:

- `base_path`: 정적 점검할 프로젝트 경로
- `target_url`: 라이브/공격 표면 점검할 배포 URL
- `openapi_url`: 직접 지정한 OpenAPI/Swagger JSON 문서 URL
- `bearer_token`, `session_cookie`, `extra_headers`: 일반 사용자 인증 정보
- `output_path`: 통합 리포트 저장 경로
- `allowed_base_path`: 저장 허용 workspace 경로

### `check_openapi_security`

OpenAPI/Swagger 문서를 탐색하거나 직접 읽어서 API 구조 기반 보안 위험 신호를 점검합니다.

주요 점검:

- 공개 OpenAPI/Swagger 문서 노출
- 전체 API 경로와 메서드 분포
- 관리자, 내부, 결제, 환불, 주문, 쿠폰, 파일, 웹훅 관련 endpoint 후보
- `{userId}`, `{orderId}`, `{fileId}` 같은 IDOR 후보 path parameter
- `role`, `isAdmin`, `userId`, `ownerId`, `price`, `amount`, `status`, `discount`, `quantity` 같은 위험 입력 필드
- 인증 요구사항이 문서상 보이지 않는 상태 변경 API
- 비즈니스 로직 수동 검토가 필요한 endpoint 후보

### `check_live_security`

배포된 URL에 실제 요청을 보내 응답을 점검합니다.

주요 점검:

- CORS 전체 허용
- CSP, X-Frame-Options, X-Content-Type-Options, HSTS 누락
- 세션 쿠키 보호 속성 누락
- 서버 배너 노출
- 에러 페이지/스택 트레이스 노출

### `check_attack_surface`

공격자가 먼저 시도할 공개 경로를 탐색합니다.

주요 점검:

- `/admin`, `/dashboard`, `/api/admin` 같은 관리자 경로 노출
- `/login`, `/forgot-password`, `/swagger`, `/openapi.json`, `/health` 같은 민감 엔드포인트 노출
- `/users/1`, `/orders/1` 같은 순차 ID 기반 데이터 노출 신호
- OPTIONS 응답의 위험한 HTTP 메서드 노출

### `check_authenticated_flows`

일반 사용자 토큰 또는 세션 쿠키로 로그인된 상태를 가정하고 권한 문제를 점검합니다.

주요 점검:

- 일반 사용자로 관리자 경로 접근 가능성
- 로그인된 상태에서 타인 ID 데이터 접근 가능성

### `export_report`

점검 도구가 반환한 Markdown 리포트를 파일로 저장합니다.

주요 입력:

- `report_content`: 저장할 리포트 내용
- `output_path`: 저장할 파일 경로
- `overwrite`: 기존 파일 덮어쓰기 여부. 기본값은 `false`
- `allowed_base_path`: 값이 있으면 해당 workspace 내부 경로에만 저장

## 리포트 형식

리포트는 대체로 다음 구조를 따릅니다.

- 점검 대상
- 감지 이슈 수
- 출시 판정
- 한눈에 보기
- 주요 이슈 요약
- 상세 이슈 목록
- 공격자 관점 평가
- 커버리지와 한계

각 이슈는 보통 아래 정보를 포함합니다.

- 이슈 이름
- 심각도
- 위치 또는 경로
- 왜 위험한가
- 공격자 시나리오

## 잘하는 것

- 출시 전에 눈에 띄는 보안 문제를 빠르게 발견
- 비개발자도 "이 서비스가 왜 위험한지" 이해 가능
- 공격자 관점에서 공개된 표면을 빠르게 훑어봄
- 일반 사용자 권한으로 발생할 수 있는 권한 상승/IDOR 신호 확인

## 한계

이 도구는 보안 사전 점검 보조 도구입니다. `기본 점검 통과`가 실제 서비스의 안전을 보증하지는 않습니다.

이 도구가 모든 프레임워크를 100% 완전하게 검증하는 것은 아닙니다.

특히 아래는 자동 점검만으로 완전하게 증명하기 어렵습니다.

- 복잡한 비즈니스 로직 권한 문제
- 멀티스텝 인증 우회
- 실제 결제/주문/정산 플로우 전체
- 인프라 내부망 정책, WAF, CDN, 클라우드 IAM 구성 전체
- 테스트 계정 없이는 재현이 어려운 세밀한 권한 문제
- GraphQL, WebSocket, 파일 다운로드, 웹훅, 업로드 후 처리처럼 서비스별 맥락이 큰 흐름
- Python, Java, Ruby, PHP, Go, Rust 등 npm 외 생태계의 전체 의존성 취약점

즉, 이 MCP는 출시 전 1차/2차 방어선에는 적합하지만, 이것만으로 절대 안전하다고 결론 내리면 안 됩니다.

## 설치

```bash
uv sync
```

## 실행

```bash
uv run python src/server.py
```

또는 등록된 스크립트를 사용할 수 있습니다.

```bash
uv run security-check-mcp
```

MCP 클라이언트에 등록할 때는 아래처럼 설정할 수 있습니다.

```json
{
  "mcpServers": {
    "security-check": {
      "command": "uv",
      "args": [
        "run",
        "security-check-mcp"
      ],
      "cwd": "/Users/yoonsu/Documents/GitHub/security-check-mcp"
    }
  }
}
```

직접 Python 파일을 실행하는 방식으로 등록해도 됩니다.

```json
{
  "mcpServers": {
    "security-check": {
      "command": "uv",
      "args": [
        "run",
        "python",
        "/Users/yoonsu/Documents/GitHub/security-check-mcp/src/server.py"
      ],
      "cwd": "/Users/yoonsu/Documents/GitHub/security-check-mcp"
    }
  }
}
```

## 사용 순서

1. `security_check`로 가능한 점검을 한 번에 실행합니다.
2. 세부 점검이 필요하면 `check_security`, `check_openapi_security`, `check_live_security`, `check_attack_surface`, `check_authenticated_flows`를 개별 실행합니다.
3. 저장이 필요하면 `output_path`를 지정하거나 `export_report`를 별도로 사용합니다.
4. Claude Code에서는 `.claude/commands/security-check.md`를 통해 `/security-check` 커스텀 명령으로 MCP 점검과 security-review 관점 검토를 함께 요청할 수 있습니다.

예시 입력:

```text
security_check(
  base_path="/path/to/project",
  target_url="https://example.com",
  openapi_url="https://example.com/openapi.json",
  bearer_token="일반 사용자 토큰",
  output_path="/path/to/project/security-report.md",
  overwrite=true,
  allowed_base_path="/path/to/project"
)
check_security(base_path="/path/to/project", skip_test_files=true)
check_openapi_security(target_url="https://example.com")
check_live_security(target_url="https://example.com")
check_attack_surface(target_url="https://example.com")
check_authenticated_flows(
  target_url="https://example.com",
  bearer_token="일반 사용자 토큰",
  reference_user_id="1",
  alternate_user_id="2"
)
export_report(
  report_content="check_security 또는 다른 점검 도구가 반환한 리포트",
  output_path="/path/to/project/security-report.md",
  overwrite=true,
  allowed_base_path="/path/to/project"
)
```

## 테스트

```bash
uv run pytest
```

## 현재 구현 상태

- 정적 코드 점검
- 라이브 응답 헤더/쿠키 점검
- 공개 공격 표면 점검
- 인증 기반 권한 점검
- 비개발자용 한국어 리포트

## 앞으로 확장할 방향

- 프레임워크별 규칙 더 확장
- 더 정교한 AST 기반 분석
- CSRF, 파일 업로드, 웹훅, 결제 플로우 전용 점검
- 테스트 계정 기반 시나리오 자동화
- 리포트 포맷 JSON/Markdown 분리

## 주의

실제 운영 서비스에 동적 점검을 수행할 때는 반드시 본인이 점검 권한을 가진 서비스에만 사용해야 합니다.
