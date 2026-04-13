import re
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# ──────────────────────────────────────────────────────────────────────────────
# 탐지 패턴
# ──────────────────────────────────────────────────────────────────────────────

# (label, regex, severity)
SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("하드코딩된 API 키",      re.compile(r'api[_-]?key\s*[=:]\s*["\'][^"\']{8,}["\']', re.IGNORECASE), "HIGH"),
    ("하드코딩된 비밀번호",    re.compile(r'password\s*[=:]\s*["\'][^"\']{4,}["\']', re.IGNORECASE),     "HIGH"),
    ("하드코딩된 시크릿",      re.compile(r'secret\s*[=:]\s*["\'][^"\']{8,}["\']', re.IGNORECASE),       "HIGH"),
    ("AWS Access Key",         re.compile(r'AKIA[0-9A-Z]{16}'),                                           "HIGH"),
    ("AWS Secret Key",         re.compile(r'aws[_-]?secret\s*[=:]\s*["\'][^"\']{20,}["\']', re.IGNORECASE), "HIGH"),
    ("하드코딩된 토큰",        re.compile(r'token\s*[=:]\s*["\'][^"\']{16,}["\']', re.IGNORECASE),       "MEDIUM"),
    ("하드코딩된 DB URL",      re.compile(r'(mysql|postgres|mongodb)\:\/\/\w+:[^@\s]+@', re.IGNORECASE),  "HIGH"),
    ("Private Key 블록",       re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'),                     "HIGH"),
]

CONSOLE_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("console.log 민감 정보 출력", re.compile(r'console\.log\s*\(.*?(password|token|secret|key|user|auth)', re.IGNORECASE), "MEDIUM"),
    ("console.log 객체 전체 출력", re.compile(r'console\.log\s*\(\s*(JSON\.stringify|req\.|res\.|user|member)'), "LOW"),
    ("print 민감 정보 출력 (Python)", re.compile(r'print\s*\(.*?(password|token|secret|key)', re.IGNORECASE), "MEDIUM"),
]

INJECTION_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("SQL Injection 가능성 (문자열 보간)", re.compile(r'query\s*\(\s*[f`"\'].*?\$\{?[^}]+\}?.*?(WHERE|SELECT|INSERT|UPDATE|DELETE)', re.IGNORECASE), "HIGH"),
    ("SQL Injection 가능성 (포맷 문자열)", re.compile(r'f["\'].*?(SELECT|INSERT|UPDATE|DELETE).*?\{'), "HIGH"),
    ("eval() 사용",                        re.compile(r'\beval\s*\('),                                 "HIGH"),
    ("exec() 사용 (Python)",               re.compile(r'\bexec\s*\(\s*[^)]*input', re.IGNORECASE),     "MEDIUM"),
]

AUTH_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("CORS 전체 허용",            re.compile(r'cors\s*\(\s*\{[^}]*origin\s*:\s*["\']?\*["\']?', re.IGNORECASE), "MEDIUM"),
    ("JWT localStorage 저장",     re.compile(r'localStorage\.setItem\s*\([^)]*token', re.IGNORECASE),           "MEDIUM"),
    ("인증 없는 admin 라우트",    re.compile(r'(app|router)\.(get|post|put|delete)\s*\(["\']\/admin', re.IGNORECASE), "MEDIUM"),
]

# 에러 응답에 스택 트레이스 노출
ERROR_EXPOSURE_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("에러 스택 트레이스 노출",   re.compile(r'(res|response)\.(json|send)\s*\([^)]*\bstack\b', re.IGNORECASE),           "HIGH"),
    ("에러 메시지 직접 노출",     re.compile(r'(res|response)\.(json|send)\s*\([^)]*err(or)?\.message', re.IGNORECASE),   "MEDIUM"),
    ("민감 정보 로그 (Java)",     re.compile(r'log\.(info|debug|warn)\s*\([^)]*password', re.IGNORECASE),                 "HIGH"),
    ("민감 정보 로그 (Python)",   re.compile(r'(logger|logging)\.(info|debug|warning)\s*\([^)]*password', re.IGNORECASE), "HIGH"),
]

# Rate Limiting 없는 인증 라우트
RATE_LIMIT_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("로그인 라우트 Rate Limit 미적용 가능성", re.compile(r'(app|router)\.(post)\s*\(["\'].*(login|signin|auth)["\'](?!.*limit)', re.IGNORECASE), "MEDIUM"),
    ("비밀번호 재설정 Rate Limit 미적용 가능성", re.compile(r'(app|router)\.(post)\s*\(["\'].*(password|reset|forgot)["\'](?!.*limit)', re.IGNORECASE), "MEDIUM"),
]

# 파일 업로드 취약점
FILE_UPLOAD_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("파일 확장자 검증 없는 업로드",  re.compile(r'(multer|upload|diskStorage)\s*\([^)]*\)', re.IGNORECASE),                    "MEDIUM"),
    ("파일명 직접 사용",              re.compile(r'(writeFile|createWriteStream)\s*\([^)]*req\.(body|file|files)', re.IGNORECASE), "HIGH"),
    ("경로 탈출 가능성",              re.compile(r'path\.(join|resolve)\s*\([^)]*req\.(body|params|query)', re.IGNORECASE),        "HIGH"),
]

# JWT / 인증 처리 오류
JWT_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("jwt.decode 사용 (검증 없음)", re.compile(r'jwt\.decode\s*\(', re.IGNORECASE), "HIGH"),
    ("응답에 password 필드 포함",   re.compile(r'(res|response)\.(json|send)\s*\(\s*(await\s+)?\w*(user|member|account)\b(?!.*select)', re.IGNORECASE), "MEDIUM"),
]

# IDOR (수평적 권한 상승) 가능성
IDOR_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("소유자 검증 없는 단건 조회 가능성", re.compile(r'findById\s*\(\s*req\.(params|query|body)\.id\s*\)', re.IGNORECASE), "MEDIUM"),
    ("소유자 검증 없는 단건 조회 가능성 (JPA)", re.compile(r'findById\s*\(\s*(id|userId|resourceId)\s*\)(?!.*UserId|.*owner)', re.IGNORECASE), "MEDIUM"),
]

ENV_GITIGNORE_FILES = {".env", ".env.local", ".env.production", ".env.development"}
CODE_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx", ".py", ".java", ".kt", ".go"}

# ──────────────────────────────────────────────────────────────────────────────
# 내부 헬퍼
# ──────────────────────────────────────────────────────────────────────────────

def _is_test_file(path: Path) -> bool:
    name = path.name.lower()
    parts = [p.lower() for p in path.parts]
    return (
        "test" in parts or "tests" in parts or "__tests__" in parts
        or name.endswith((".test.ts", ".test.js", ".spec.ts", ".spec.js", "_test.py"))
        or "test" in name
    )


def _scan_patterns(
    files: list[Path],
    patterns: list[tuple[str, re.Pattern, str]],
) -> list[dict]:
    findings: list[dict] = []
    for file in files:
        try:
            lines = file.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            continue
        for lineno, line in enumerate(lines, start=1):
            for label, pattern, severity in patterns:
                if pattern.search(line):
                    findings.append({
                        "severity": severity,
                        "label": label,
                        "file": str(file),
                        "line": lineno,
                        "snippet": line.strip()[:120],
                    })
    return findings


def _check_env_gitignore(base: Path) -> list[dict]:
    findings: list[dict] = []
    gitignore_path = base / ".gitignore"
    if not gitignore_path.exists():
        findings.append({
            "severity": "HIGH",
            "label": ".gitignore 파일 없음",
            "file": str(base),
            "line": 0,
            "snippet": ".gitignore가 없으면 .env 파일이 커밋될 수 있습니다.",
        })
        return findings

    gitignore_content = gitignore_path.read_text(encoding="utf-8")
    for env_file in ENV_GITIGNORE_FILES:
        if (base / env_file).exists() and env_file not in gitignore_content:
            findings.append({
                "severity": "HIGH",
                "label": f".env 파일이 .gitignore에 없음 ({env_file})",
                "file": str(gitignore_path),
                "line": 0,
                "snippet": f"{env_file}이 존재하지만 .gitignore에 누락되어 있습니다.",
            })
    return findings


def _run_npm_audit(base: Path) -> str | None:
    if not (base / "package.json").exists():
        return None
    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=str(base),
            capture_output=True,
            text=True,
            timeout=60,
        )
        return result.stdout or result.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def _format_findings(findings: list[dict]) -> str:
    if not findings:
        return ""
    lines = []
    for f in findings:
        loc = f"{f['file']}:{f['line']}" if f["line"] else f['file']
        lines.append(f"  [{f['severity']}] {f['label']}\n    위치: {loc}\n    내용: {f['snippet']}")
    return "\n\n".join(lines)


def _format_npm_audit(raw: str) -> str:
    try:
        import json
        data = json.loads(raw)
        meta = data.get("metadata", {})
        vulns = meta.get("vulnerabilities", {})
        total = sum(vulns.values()) if isinstance(vulns, dict) else 0
        if total == 0:
            return "npm audit: 취약점 없음"
        parts = [f"{k}={v}" for k, v in vulns.items() if v]
        return f"npm audit: 총 {total}개 취약점 ({', '.join(parts)})\n(상세 내용은 `npm audit` 직접 실행 권장)"
    except Exception:
        return f"npm audit 결과:\n{raw[:500]}"


# ──────────────────────────────────────────────────────────────────────────────
# Tool 등록
# ──────────────────────────────────────────────────────────────────────────────

def register_security_tools(mcp: FastMCP) -> None:

    @mcp.tool()
    def check_security(
        base_path: str,
        skip_test_files: bool = True,
    ) -> str:
        """
        코드베이스에서 보안 취약점을 점검한다.

        사용자가 "보안 점검해줘", "시크릿 키 노출 확인해줘", "보안 이슈 찾아줘" 등의 요청을 하면
        이 Tool을 호출한다.

        점검 항목:
          - 하드코딩된 시크릿 (API 키, 비밀번호, AWS 키, DB URL 등)
          - .env 파일의 .gitignore 누락
          - 민감 정보 console.log 출력
          - SQL Injection / eval() 가능성
          - CORS 전체 허용, JWT localStorage 저장, 인증 없는 admin 라우트
          - npm audit (package.json이 있는 경우)

        Parameters
        ----------
        base_path : str
            점검할 프로젝트 루트 디렉터리 (예: "/Users/user/my-project")
        skip_test_files : bool
            True(기본값)면 테스트 파일은 오탐 방지를 위해 제외
        """
        base = Path(base_path)
        if not base.exists():
            return f"오류: 경로가 존재하지 않습니다 - {base_path}"

        all_files = [
            f for f in base.rglob("*")
            if f.is_file()
            and f.suffix in CODE_EXTENSIONS
            and ".git" not in f.parts
            and "node_modules" not in f.parts
            and "venv" not in f.parts
            and ".gradle" not in f.parts
            and "build" not in f.parts
            and (not skip_test_files or not _is_test_file(f))
        ]

        secret_findings       = _scan_patterns(all_files, SECRET_PATTERNS)
        console_findings      = _scan_patterns(all_files, CONSOLE_PATTERNS)
        injection_findings    = _scan_patterns(all_files, INJECTION_PATTERNS)
        auth_findings         = _scan_patterns(all_files, AUTH_PATTERNS)
        error_findings        = _scan_patterns(all_files, ERROR_EXPOSURE_PATTERNS)
        rate_limit_findings   = _scan_patterns(all_files, RATE_LIMIT_PATTERNS)
        file_upload_findings  = _scan_patterns(all_files, FILE_UPLOAD_PATTERNS)
        jwt_findings          = _scan_patterns(all_files, JWT_PATTERNS)
        idor_findings         = _scan_patterns(all_files, IDOR_PATTERNS)
        env_findings          = _check_env_gitignore(base)
        npm_audit_result      = _run_npm_audit(base)

        all_findings = (
            secret_findings + env_findings + injection_findings
            + auth_findings + error_findings + rate_limit_findings
            + file_upload_findings + jwt_findings + idor_findings
            + console_findings
        )
        high   = [f for f in all_findings if f["severity"] == "HIGH"]
        medium = [f for f in all_findings if f["severity"] == "MEDIUM"]
        low    = [f for f in all_findings if f["severity"] == "LOW"]

        sections = [
            f"## 보안 점검 결과: {base_path}",
            f"스캔 파일 수: {len(all_files)}개",
            f"발견된 이슈: HIGH={len(high)}, MEDIUM={len(medium)}, LOW={len(low)}",
            "",
        ]

        if high:
            sections.append("### HIGH (즉시 수정 필요)")
            sections.append(_format_findings(high))
            sections.append("")

        if medium:
            sections.append("### MEDIUM (검토 필요)")
            sections.append(_format_findings(medium))
            sections.append("")

        if low:
            sections.append("### LOW (참고)")
            sections.append(_format_findings(low))
            sections.append("")

        if npm_audit_result:
            sections.append("### 의존성 취약점")
            sections.append(_format_npm_audit(npm_audit_result))
            sections.append("")

        if not all_findings and not npm_audit_result:
            sections.append("이슈가 발견되지 않았습니다.")

        return "\n".join(sections)
