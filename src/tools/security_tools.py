import json
import re
import subprocess
from collections import Counter
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from mcp.server.fastmcp import FastMCP


SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", ".gradle", "build", "dist", "target", "__pycache__"}
CODE_EXTENSIONS = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".py", ".java", ".kt", ".kts", ".go", ".rb",
    ".php", ".cs", ".scala", ".swift", ".rs",
}
TEXT_CONFIG_EXTENSIONS = {".json", ".yml", ".yaml", ".env", ".toml", ".ini", ".conf"}
ENV_GITIGNORE_FILES = {".env", ".env.local", ".env.production", ".env.development", ".env.test"}
FRAMEWORK_HINTS = {
    "next.js": ["next.config.js", "next.config.mjs", "next.config.ts"],
    "nuxt": ["nuxt.config.ts", "nuxt.config.js"],
    "django": ["manage.py"],
    "flask": ["wsgi.py", "app.py"],
    "spring": ["pom.xml", "build.gradle", "build.gradle.kts"],
    "rails": ["config/routes.rb", "Gemfile"],
    "laravel": ["artisan", "composer.json"],
}


class IssueDefinition(dict):
    pass


ISSUE_DEFINITIONS: dict[str, IssueDefinition] = {
    "하드코딩된 API 키": {
        "category": "비밀정보 노출",
        "risk": "저장소 유출이나 로그 열람만으로 외부 API가 악용될 수 있습니다.",
        "attack": "공격자는 키를 복사해 결제형 API를 호출하거나 내부 데이터에 접근할 수 있습니다.",
        "fix": "키를 환경변수나 시크릿 매니저로 이동하고, 이미 노출된 키는 즉시 폐기 후 재발급하세요.",
        "owner": "백엔드 또는 인프라 담당 개발자",
        "verify": "코드와 배포 환경에서 해당 키가 더 이상 보이지 않고, 재발급된 키만 정상 동작하는지 확인하세요.",
    },
    "하드코딩된 비밀번호": {
        "category": "비밀정보 노출",
        "risk": "소스 유출만으로 운영 계정이 탈취될 수 있습니다.",
        "attack": "공격자는 DB, 관리자 계정, 외부 서비스 계정에 직접 로그인할 수 있습니다.",
        "fix": "비밀번호를 코드에서 제거하고 시크릿 매니저로 이동한 뒤, 기존 비밀번호를 즉시 변경하세요.",
    },
    "하드코딩된 시크릿": {
        "category": "비밀정보 노출",
        "risk": "서명키가 노출되면 세션, 토큰, 웹훅 검증이 무력화될 수 있습니다.",
        "attack": "공격자는 위조 토큰을 만들거나 서버를 신뢰하는 것처럼 요청을 보낼 수 있습니다.",
        "fix": "시크릿을 코드에서 제거하고 재발급하세요. JWT, 쿠키 서명, 웹훅 검증키는 모두 교체가 필요합니다.",
    },
    "AWS Access Key": {
        "category": "클라우드 계정 탈취",
        "risk": "클라우드 리소스가 직접 탈취될 수 있습니다.",
        "attack": "공격자는 S3, ECS, Lambda, RDS 등 권한 범위 안의 자산을 바로 조회하거나 삭제할 수 있습니다.",
        "fix": "키를 즉시 비활성화하고 IAM 최소 권한 정책으로 교체하세요. 장기 키 대신 역할 기반 인증을 사용하세요.",
    },
    "AWS Secret Key": {
        "category": "클라우드 계정 탈취",
        "risk": "다른 식별자와 조합되면 운영 계정이 탈취될 수 있습니다.",
        "attack": "유출된 비밀키는 공격자가 클라우드 API를 호출하는 데 사용됩니다.",
        "fix": "비밀키를 폐기하고 재발급하세요. 코드와 CI 로그에 남아 있는지도 함께 점검하세요.",
    },
    "하드코딩된 토큰": {
        "category": "비밀정보 노출",
        "risk": "외부 연동이나 내부 API 호출 권한이 그대로 재사용될 수 있습니다.",
        "attack": "공격자는 토큰을 복사해 API를 호출하거나 사용자로 가장할 수 있습니다.",
        "fix": "토큰을 코드에서 제거하고 만료 또는 재발급 처리하세요.",
    },
    "하드코딩된 DB URL": {
        "category": "데이터베이스 노출",
        "risk": "DB 자격증명 유출로 운영 데이터가 직접 노출될 수 있습니다.",
        "attack": "공격자는 DB에 접속해 개인정보를 조회, 수정, 삭제할 수 있습니다.",
        "fix": "DB 접속 문자열을 환경변수로 이동하고 비밀번호를 회전하세요. 외부 접속 허용 정책도 재검토하세요.",
    },
    "Private Key 블록": {
        "category": "비밀정보 노출",
        "risk": "서버 인증서, SSH, JWT 서명 등 핵심 신뢰 체인이 붕괴될 수 있습니다.",
        "attack": "공격자는 키를 이용해 서버에 접속하거나 위조 서명을 만들 수 있습니다.",
        "fix": "키를 즉시 폐기하고 재발급하세요. 저장소 이력과 배포 로그에 남아 있는지도 확인하세요.",
    },
    ".gitignore 파일 없음": {
        "category": "배포 실수 위험",
        "risk": "민감한 설정 파일이 실수로 저장소에 포함될 가능성이 큽니다.",
        "attack": "공격자는 공개 저장소나 협업 도구에서 `.env` 파일을 바로 얻을 수 있습니다.",
        "fix": "프로젝트 루트에 `.gitignore`를 추가하고 민감 파일 패턴을 명시하세요.",
    },
    "에러 스택 트레이스 노출": {
        "category": "정보 노출",
        "risk": "공격자에게 내부 파일 경로, 라이브러리, 쿼리 구조가 그대로 공개됩니다.",
        "attack": "에러 응답을 반복 유도해 공격 표면과 취약 라이브러리를 빠르게 파악할 수 있습니다.",
        "fix": "운영 환경에서는 사용자에게 일반화된 에러만 반환하고 상세 로그는 서버 내부에만 남기세요.",
    },
    "에러 메시지 직접 노출": {
        "category": "정보 노출",
        "risk": "데이터 구조와 인증 흐름이 노출되어 후속 공격 난도가 낮아집니다.",
        "attack": "공격자는 메시지 차이를 이용해 계정 존재 여부, 쿼리 구조, 검증 로직을 추론합니다.",
        "fix": "클라이언트 응답은 일반화하고, 세부 원인은 내부 로그로만 남기세요.",
    },
    "민감 정보 로그 (Java)": {
        "category": "로그 유출",
        "risk": "운영 로그 시스템만 읽어도 비밀번호가 노출될 수 있습니다.",
        "attack": "공격자는 로그 수집기, APM, 백업 파일에서 자격증명을 확보합니다.",
        "fix": "민감 필드를 로깅하지 말고, 마스킹 필터를 적용하세요.",
    },
    "민감 정보 로그 (Python)": {
        "category": "로그 유출",
        "risk": "운영 로그 시스템만 읽어도 민감 정보가 노출될 수 있습니다.",
        "attack": "공격자는 로그 접근권한만 확보해도 인증정보를 수집할 수 있습니다.",
        "fix": "민감 필드는 마스킹하고, 인증정보는 절대 로그에 남기지 마세요.",
    },
    "SQL Injection 가능성 (문자열 보간)": {
        "category": "입력값 주입",
        "risk": "사용자 입력이 쿼리에 직접 들어가면 데이터 탈취나 변경이 가능합니다.",
        "attack": "공격자는 `' OR 1=1 --` 같은 입력으로 인증 우회나 대량 데이터 조회를 시도합니다.",
        "fix": "문자열 조합 대신 prepared statement, parameter binding, ORM placeholder를 사용하세요.",
    },
    "SQL Injection 가능성 (포맷 문자열)": {
        "category": "입력값 주입",
        "risk": "포맷 문자열로 쿼리를 만들면 DB 전체가 공격 표면이 됩니다.",
        "attack": "공격자는 권한 상승, 데이터 추출, 테이블 삭제까지 시도할 수 있습니다.",
        "fix": "동적 SQL 생성은 화이트리스트 기반으로 제한하고 값은 반드시 바인딩하세요.",
    },
    "eval() 사용": {
        "category": "원격 코드 실행",
        "risk": "외부 입력이 섞이면 서버에서 임의 코드가 실행될 수 있습니다.",
        "attack": "공격자는 시스템 명령 실행, 파일 읽기, 서비스 장악으로 이어갈 수 있습니다.",
        "fix": "`eval` 사용을 제거하고 명시적 파서나 안전한 매핑 구조로 대체하세요.",
    },
    "exec() 사용 (Python)": {
        "category": "원격 코드 실행",
        "risk": "입력값이 실행되면 서버 전체가 장악될 수 있습니다.",
        "attack": "공격자는 파일 시스템 접근, 환경변수 탈취, 내부망 스캔을 수행할 수 있습니다.",
        "fix": "`exec`를 제거하고 허용된 동작만 선택 실행하는 구조로 바꾸세요.",
    },
    "Command Injection 가능성": {
        "category": "원격 코드 실행",
        "risk": "사용자 입력이 쉘 명령에 섞이면 서버 명령이 실행됩니다.",
        "attack": "공격자는 `; curl ...` 같은 페이로드로 원격 셸을 열 수 있습니다.",
        "fix": "쉘 실행을 피하고, 꼭 필요하면 인자 배열과 화이트리스트 검증을 사용하세요.",
    },
    "SSRF 가능성": {
        "category": "서버사이드 요청 위조",
        "risk": "서버가 대신 내부망이나 메타데이터 서비스에 요청을 보낼 수 있습니다.",
        "attack": "공격자는 AWS/GCP 메타데이터, 내부 관리자 페이지, 사설 API를 조회할 수 있습니다.",
        "fix": "외부 URL 입력을 그대로 요청하지 말고 허용 도메인 목록과 사설 IP 차단을 적용하세요.",
    },
    "CORS 전체 허용": {
        "category": "브라우저 정책 완화",
        "risk": "의도하지 않은 출처에서 API를 호출할 수 있습니다.",
        "attack": "공격자는 악성 웹사이트에서 사용자의 브라우저를 이용해 API를 호출합니다.",
        "fix": "운영 도메인만 명시적으로 허용하고 자격증명 사용 시 `*`를 금지하세요.",
    },
    "JWT localStorage 저장": {
        "category": "세션 탈취",
        "risk": "XSS가 발생하면 토큰이 즉시 탈취됩니다.",
        "attack": "공격자는 스크립트 한 줄로 세션 토큰을 외부로 전송할 수 있습니다.",
        "fix": "가능하면 `HttpOnly`, `Secure`, `SameSite`가 설정된 쿠키를 사용하세요.",
    },
    "인증 없는 admin 라우트": {
        "category": "권한 검증 누락",
        "risk": "관리자 기능이 외부에 직접 노출될 수 있습니다.",
        "attack": "공격자는 관리자 경로를 직접 호출해 데이터 열람이나 설정 변경을 시도합니다.",
        "fix": "관리자 라우트에 인증과 역할 검증 미들웨어를 강제하세요.",
    },
    "로그인 라우트 Rate Limit 미적용 가능성": {
        "category": "계정 탈취 방어 부족",
        "risk": "무차별 대입 공격에 취약할 수 있습니다.",
        "attack": "공격자는 비밀번호 추측을 대량으로 시도해 계정을 탈취합니다.",
        "fix": "IP, 계정, 디바이스 기준 rate limit과 계정 잠금 정책을 추가하세요.",
    },
    "비밀번호 재설정 Rate Limit 미적용 가능성": {
        "category": "계정 탈취 방어 부족",
        "risk": "비밀번호 재설정 기능이 스팸·무차별 시도의 표적이 됩니다.",
        "attack": "공격자는 이메일 폭탄, 토큰 추측, 계정 유무 확인을 시도합니다.",
        "fix": "재설정 요청에 rate limit, CAPTCHA, 단일 사용 토큰, 만료 시간을 적용하세요.",
    },
    "파일 확장자 검증 없는 업로드": {
        "category": "악성 파일 업로드",
        "risk": "실행 파일이나 스크립트가 업로드될 수 있습니다.",
        "attack": "공격자는 웹셸, 대용량 파일, 악성 스크립트를 업로드해 서버를 악용합니다.",
        "fix": "확장자와 MIME 타입을 모두 검사하고 저장 경로를 격리하세요.",
    },
    "파일명 직접 사용": {
        "category": "파일 시스템 조작",
        "risk": "사용자 입력이 파일 경로에 직접 쓰이면 덮어쓰기와 경로 조작이 가능합니다.",
        "attack": "공격자는 운영 파일 덮어쓰기, 임시 파일 충돌, 예기치 않은 위치 저장을 유도합니다.",
        "fix": "업로드 파일명은 서버가 새로 생성하고 원본 이름은 표시 용도로만 보관하세요.",
    },
    "경로 탈출 가능성": {
        "category": "파일 시스템 조작",
        "risk": "상위 디렉터리 접근으로 민감 파일이 노출될 수 있습니다.",
        "attack": "공격자는 `../../` 패턴으로 설정 파일이나 소스 파일을 읽으려 시도합니다.",
        "fix": "사용자 입력을 경로에 직접 넣지 말고 기준 디렉터리 검증을 강제하세요.",
    },
    "jwt.decode 사용 (검증 없음)": {
        "category": "인증 우회",
        "risk": "서명 검증 없이 토큰 내용을 신뢰하면 누구나 관리자 토큰을 꾸밀 수 있습니다.",
        "attack": "공격자는 `role=admin` 같은 값을 넣은 가짜 토큰을 보낼 수 있습니다.",
        "fix": "`decode` 대신 서명과 만료를 검증하는 `verify` 계열 API를 사용하세요.",
    },
    "응답에 password 필드 포함": {
        "category": "개인정보 노출",
        "risk": "민감 필드가 API 응답으로 외부에 노출될 수 있습니다.",
        "attack": "공격자는 정상 요청만으로 해시나 비밀번호 필드를 수집할 수 있습니다.",
        "fix": "응답 DTO를 분리하고 민감 필드는 기본적으로 제외하세요.",
    },
    "소유자 검증 없는 단건 조회 가능성": {
        "category": "권한 검증 누락",
        "risk": "다른 사용자의 데이터에 접근할 수 있는 IDOR가 발생할 수 있습니다.",
        "attack": "공격자는 ID 값만 바꿔 다른 사용자의 주문, 문서, 계정 정보를 조회합니다.",
        "fix": "리소스 조회 시 `현재 사용자`와 `리소스 소유자`를 함께 검증하세요.",
    },
    "소유자 검증 없는 단건 조회 가능성 (JPA)": {
        "category": "권한 검증 누락",
        "risk": "JPA 조회가 인증 컨텍스트와 분리되면 수평 권한 상승이 발생할 수 있습니다.",
        "attack": "공격자는 다른 사용자의 리소스 ID를 넣어 데이터에 접근합니다.",
        "fix": "ID 단독 조회 대신 `id + ownerId` 조건으로 조회하거나 후속 소유자 검증을 추가하세요.",
    },
    "console.log 민감 정보 출력": {
        "category": "로그 유출",
        "risk": "브라우저 콘솔과 서버 로그에서 민감 정보가 새어 나갈 수 있습니다.",
        "attack": "공격자는 디버그 로그, 브라우저 공유 화면, 원격 수집 로그를 통해 데이터를 확보합니다.",
        "fix": "민감 필드 로깅을 제거하고 디버그 로그는 운영에서 비활성화하세요.",
    },
    "console.log 객체 전체 출력": {
        "category": "로그 유출",
        "risk": "요청/응답 전체를 찍으면 토큰과 개인정보가 함께 저장될 수 있습니다.",
        "attack": "공격자는 세션 정보, 내부 헤더, 개인정보를 로그에서 수집합니다.",
        "fix": "필요한 필드만 선택적으로 로그하고 토큰과 쿠키는 항상 마스킹하세요.",
    },
    "print 민감 정보 출력 (Python)": {
        "category": "로그 유출",
        "risk": "개발 편의용 출력이 운영 로그에 남을 수 있습니다.",
        "attack": "공격자는 로그 수집기, 표준출력 백업, 컨테이너 로그에서 민감 정보를 얻습니다.",
        "fix": "민감 정보 출력 코드를 제거하고 구조화된 로깅 + 마스킹 정책을 적용하세요.",
    },
    "디버그 모드 활성화": {
        "category": "운영 설정 취약",
        "risk": "운영 환경에서 디버그가 켜져 있으면 상세 정보와 개발 기능이 노출됩니다.",
        "attack": "공격자는 디버그 페이지, 상세 에러, 개발용 인터페이스를 발판으로 삼습니다.",
        "fix": "운영 배포에서는 디버그를 항상 끄고 환경별 설정을 분리하세요.",
    },
    "시큐어 쿠키 설정 누락 가능성": {
        "category": "세션 보호 부족",
        "risk": "쿠키가 자바스크립트나 비암호화 연결을 통해 탈취될 수 있습니다.",
        "attack": "공격자는 XSS나 네트워크 중간자 공격과 결합해 세션을 빼앗을 수 있습니다.",
        "fix": "세션/인증 쿠키에 `HttpOnly`, `Secure`, `SameSite`를 적용하세요.",
    },
    "보안 헤더 설정 부재 가능성": {
        "category": "브라우저 보호 부족",
        "risk": "기본 보안 헤더가 없으면 클릭재킹, MIME 스니핑, 일부 XSS 완화가 빠질 수 있습니다.",
        "attack": "공격자는 브라우저 동작을 악용해 피싱 화면 삽입이나 취약한 리소스 해석을 유도할 수 있습니다.",
        "fix": "Node 계열 서버라면 `helmet` 같은 보안 헤더 미들웨어를 적용하고 필요한 정책만 예외 처리하세요.",
    },
    "FastAPI TrustedHostMiddleware 부재 가능성": {
        "category": "호스트 헤더 검증 부족",
        "risk": "허용 호스트 검증이 없으면 호스트 헤더 기반 우회나 잘못된 URL 생성 문제가 생길 수 있습니다.",
        "attack": "공격자는 악성 Host 헤더를 보내 비밀번호 재설정 링크나 캐시 키를 오염시킬 수 있습니다.",
        "fix": "`TrustedHostMiddleware`를 추가하고 실제 서비스 도메인만 허용하세요.",
    },
    "Django DEBUG 활성화": {
        "category": "운영 설정 취약",
        "risk": "운영 환경에서 Django DEBUG가 켜져 있으면 상세 예외와 내부 설정이 노출됩니다.",
        "attack": "공격자는 에러 페이지에서 경로, 패키지, 환경설정 정보를 수집해 후속 공격에 활용합니다.",
        "fix": "운영 설정에서 `DEBUG = False`로 강제하고 환경별 설정 파일을 분리하세요.",
    },
    "Django ALLOWED_HOSTS 전체 허용 가능성": {
        "category": "호스트 헤더 검증 부족",
        "risk": "허용 호스트를 너무 넓게 열면 호스트 헤더 공격 위험이 커집니다.",
        "attack": "공격자는 위조 Host 헤더로 링크 생성, 캐시 오염, 보안 검증 우회를 시도할 수 있습니다.",
        "fix": "`ALLOWED_HOSTS`에 실제 운영 도메인만 명시하세요.",
    },
    "Flask DEBUG 활성화": {
        "category": "운영 설정 취약",
        "risk": "Flask 디버그 콘솔이 열리면 심각한 정보 노출과 코드 실행 위험이 생깁니다.",
        "attack": "공격자는 디버그 페이지를 통해 내부 상태를 파악하거나 원격 코드를 노릴 수 있습니다.",
        "fix": "운영 배포에서는 `debug=True`를 제거하고 WSGI 서버와 분리된 설정을 사용하세요.",
    },
    "Spring Security CSRF 비활성화": {
        "category": "CSRF 방어 부족",
        "risk": "브라우저 기반 세션 인증 서비스에서 CSRF 방어를 끄면 요청 위조 공격이 가능해집니다.",
        "attack": "공격자는 사용자가 로그인한 상태를 이용해 비밀번호 변경, 결제, 관리자 작업을 강제로 실행시킵니다.",
        "fix": "세션 기반 인증이면 CSRF 보호를 유지하고, API 토큰 구조라면 그 근거를 리포트에 남기세요.",
    },
    "Spring permitAll 과다 사용 가능성": {
        "category": "권한 검증 누락",
        "risk": "민감한 경로까지 `permitAll`이 적용되면 인증 없이 접근될 수 있습니다.",
        "attack": "공격자는 공개되면 안 되는 API를 직접 호출해 데이터 열람이나 기능 실행을 시도합니다.",
        "fix": "공개 경로만 최소한으로 `permitAll` 하고 나머지는 인증을 기본값으로 두세요.",
    },
    "Spring CORS 전체 허용": {
        "category": "브라우저 정책 완화",
        "risk": "의도하지 않은 외부 사이트가 사용자의 브라우저로 API를 호출할 수 있습니다.",
        "attack": "공격자는 악성 프론트엔드에서 피해자의 세션을 이용해 요청을 보냅니다.",
        "fix": "`@CrossOrigin` 또는 CORS 설정에 운영 도메인만 허용하세요.",
    },
    "Next.js 환경변수 공개 노출 가능성": {
        "category": "비밀정보 노출",
        "risk": "클라이언트 번들에 포함된 환경변수는 누구나 브라우저에서 볼 수 있습니다.",
        "attack": "공격자는 프론트엔드 자바스크립트를 분석해 API 키나 내부 엔드포인트를 추출합니다.",
        "fix": "`NEXT_PUBLIC_` 접두사가 없는 값만 서버 전용으로 두고, 민감값은 절대 클라이언트로 보내지 마세요.",
    },
    "Next.js 이미지 원격 도메인 전체 허용 가능성": {
        "category": "외부 리소스 신뢰 과다",
        "risk": "원격 이미지 도메인을 과하게 열면 의도하지 않은 외부 컨텐츠를 신뢰하게 됩니다.",
        "attack": "공격자는 이미지 경로를 악용해 추적, 피싱 유도, 예기치 않은 외부 요청을 유발할 수 있습니다.",
        "fix": "`next.config`의 이미지 허용 도메인을 실제 사용하는 도메인으로만 제한하세요.",
    },
    "NestJS ValidationPipe 부재 가능성": {
        "category": "입력값 검증 부족",
        "risk": "기본 입력 검증이 없으면 예상하지 못한 필드와 타입이 그대로 서비스 로직으로 들어갑니다.",
        "attack": "공격자는 검증되지 않은 요청으로 권한 플래그 우회, 필드 오염, 예외 유발을 시도합니다.",
        "fix": "전역 `ValidationPipe`를 적용하고 `whitelist`, `forbidNonWhitelisted` 옵션을 검토하세요.",
    },
    "Rails force_ssl 비활성 가능성": {
        "category": "전송 구간 보호 부족",
        "risk": "HTTPS 강제가 없으면 쿠키와 세션이 평문 연결로 노출될 수 있습니다.",
        "attack": "공격자는 중간자 공격으로 인증 쿠키를 가로챌 수 있습니다.",
        "fix": "운영 환경에서 `config.force_ssl = true`를 설정하세요.",
    },
    "Rails forgery protection 비활성화": {
        "category": "CSRF 방어 부족",
        "risk": "브라우저 세션 기반 서비스에서 요청 위조 공격이 가능해집니다.",
        "attack": "공격자는 사용자가 로그인한 브라우저를 이용해 중요 요청을 강제로 보내게 만듭니다.",
        "fix": "`skip_forgery_protection`을 제거하거나 필요한 API 경로만 별도 분리하세요.",
    },
    "Laravel APP_DEBUG 활성화": {
        "category": "운영 설정 취약",
        "risk": "운영 환경에서 상세 예외와 내부 설정이 노출될 수 있습니다.",
        "attack": "공격자는 오류 페이지에서 경로, 쿼리, 환경설정 단서를 수집합니다.",
        "fix": "운영 `.env`에서 `APP_DEBUG=false`로 두고 배포 환경별 파일을 분리하세요.",
    },
    "Laravel APP_KEY 누락 가능성": {
        "category": "애플리케이션 키 설정 오류",
        "risk": "앱 키가 비어 있으면 암호화와 세션 보안에 심각한 문제가 생길 수 있습니다.",
        "attack": "공격자는 취약한 암호화 구성을 이용해 세션 위조나 데이터 변조를 노릴 수 있습니다.",
        "fix": "운영 환경에 유효한 `APP_KEY`를 설정하고, 누락 상태로 배포하지 마세요.",
    },
    "라이브 서비스 CORS 전체 허용": {
        "category": "브라우저 정책 완화",
        "risk": "실제 배포 서비스가 모든 출처를 허용하면 악성 사이트에서 사용자 브라우저를 악용할 수 있습니다.",
        "attack": "공격자는 피싱 사이트에서 사용자의 세션으로 API 요청을 보내게 만듭니다.",
        "fix": "운영 서비스의 CORS 응답 헤더를 실제 프론트엔드 도메인만 허용하도록 제한하세요.",
    },
    "라이브 서비스 CSP 헤더 누락": {
        "category": "브라우저 보호 부족",
        "risk": "콘텐츠 보안 정책이 없으면 XSS 피해 범위를 줄이기 어렵습니다.",
        "attack": "공격자는 스크립트 삽입 성공 시 더 쉽게 세션 탈취와 화면 변조를 수행합니다.",
        "fix": "`Content-Security-Policy`를 추가하고 스크립트 출처를 최소화하세요.",
    },
    "라이브 서비스 클릭재킹 방어 누락": {
        "category": "브라우저 보호 부족",
        "risk": "프레임 삽입 방어가 없으면 클릭재킹 공격이 가능할 수 있습니다.",
        "attack": "공격자는 숨겨진 iframe 위에 가짜 UI를 올려 중요 버튼 클릭을 유도합니다.",
        "fix": "`X-Frame-Options: DENY` 또는 `CSP frame-ancestors`를 설정하세요.",
    },
    "라이브 서비스 MIME 스니핑 방어 누락": {
        "category": "브라우저 보호 부족",
        "risk": "브라우저가 MIME 타입을 추측하면 일부 컨텐츠 해석 문제가 생길 수 있습니다.",
        "attack": "공격자는 잘못된 파일 해석을 유도해 스크립트 실행 가능성을 높일 수 있습니다.",
        "fix": "`X-Content-Type-Options: nosniff`를 설정하세요.",
    },
    "라이브 서비스 HSTS 누락": {
        "category": "전송 구간 보호 부족",
        "risk": "HTTPS 사이트인데 HSTS가 없으면 초기 연결 강제력이 약합니다.",
        "attack": "공격자는 첫 접속이나 링크 변조 상황에서 HTTP 다운그레이드를 시도할 수 있습니다.",
        "fix": "HTTPS 서비스에는 `Strict-Transport-Security`를 설정하세요.",
    },
    "라이브 서비스 세션 쿠키 보호 속성 누락": {
        "category": "세션 보호 부족",
        "risk": "실제 배포 쿠키에 보호 속성이 없으면 세션 탈취 위험이 커집니다.",
        "attack": "공격자는 XSS나 네트워크 공격과 결합해 세션 쿠키를 훔칩니다.",
        "fix": "세션/인증 쿠키에 `HttpOnly`, `Secure`, `SameSite`를 모두 설정하세요.",
    },
    "라이브 서비스 서버 배너 노출": {
        "category": "정보 노출",
        "risk": "서버 종류와 버전이 노출되면 공격자가 취약한 조합을 더 쉽게 찾습니다.",
        "attack": "공격자는 배너 정보를 기반으로 알려진 취약점 공격 대상을 빠르게 고릅니다.",
        "fix": "불필요한 `Server`/`X-Powered-By` 헤더를 숨기거나 최소화하세요.",
    },
    "라이브 서비스 에러 페이지 노출": {
        "category": "정보 노출",
        "risk": "실제 서비스 응답에서 스택 트레이스나 프레임워크 에러 페이지가 노출될 수 있습니다.",
        "attack": "공격자는 에러 응답만으로 내부 구조와 라이브러리를 파악합니다.",
        "fix": "운영 환경에서는 일반화된 에러 페이지와 내부 전용 로그를 사용하세요.",
    },
    "관리자 경로 무인증 노출 가능성": {
        "category": "권한 검증 누락",
        "risk": "관리자 화면이나 관리자 API가 인증 없이 열려 있을 수 있습니다.",
        "attack": "공격자는 `/admin`, `/dashboard`, `/manage` 같은 경로를 바로 호출해 기능을 탐색합니다.",
        "fix": "관리자 경로는 로그인과 역할 검증 뒤에만 노출하고, 미인증 상태에서는 401/403을 반환하세요.",
        "owner": "백엔드 인증/권한 담당 개발자",
        "verify": "로그인하지 않은 상태와 일반 사용자 상태에서 관리자 경로가 401 또는 403을 반환하는지 확인하세요.",
    },
    "민감 엔드포인트 공개 노출 가능성": {
        "category": "공격 표면 과다 노출",
        "risk": "로그인, 재설정, 내부 상태 확인, 문서 엔드포인트가 과하게 노출되어 공격자가 탐색하기 쉬워집니다.",
        "attack": "공격자는 공개 엔드포인트를 수집한 뒤 로그인 추측, 계정 유무 확인, 내부 구조 파악을 시도합니다.",
        "fix": "정말 공개가 필요한 경로만 남기고, 나머지는 인증·IP 제한·비공개화 여부를 검토하세요.",
    },
    "위험한 HTTP 메서드 노출 가능성": {
        "category": "공격 표면 과다 노출",
        "risk": "PUT/DELETE/PATCH/TRACE 같은 메서드가 예상보다 넓게 열려 있을 수 있습니다.",
        "attack": "공격자는 메서드 허용 범위를 탐색해 우회 요청이나 취약한 핸들러 호출을 시도합니다.",
        "fix": "실제로 필요한 메서드만 허용하고, OPTIONS/Allow 응답도 최소화하세요.",
    },
    "순차 ID 기반 데이터 노출 가능성": {
        "category": "권한 검증 누락",
        "risk": "숫자 ID 기반 리소스가 인증 없이 조회되면 IDOR로 이어질 수 있습니다.",
        "attack": "공격자는 `/users/1`, `/orders/2`, `/documents/3`처럼 ID만 바꿔 다른 사람 데이터를 조회합니다.",
        "fix": "리소스 조회 시 소유자 검증을 강제하고, 공개 리소스가 아니라면 인증 없는 200 응답을 막으세요.",
    },
    "일반 사용자로 관리자 경로 접근 가능성": {
        "category": "권한 상승",
        "risk": "일반 사용자 권한으로 관리자 화면이나 관리자 API가 열리면 서비스 전체가 탈취될 수 있습니다.",
        "attack": "공격자는 정상 계정 하나만 만든 뒤 관리자 경로를 직접 호출해 설정 변경, 회원 조회, 데이터 삭제를 시도합니다.",
        "fix": "관리자 경로마다 역할 검증을 서버에서 강제하고, 프론트엔드 숨김 처리만으로 끝내지 마세요.",
    },
    "인증 상태 IDOR 가능성": {
        "category": "권한 검증 누락",
        "risk": "로그인된 사용자가 다른 사람 ID로 데이터를 조회할 수 있으면 개인정보 유출로 이어집니다.",
        "attack": "공격자는 본인 계정으로 로그인한 뒤 `/users/2`, `/orders/2`처럼 ID만 바꿔 다른 사람 데이터를 조회합니다.",
        "fix": "리소스 조회와 수정에서 `현재 로그인 사용자`와 `요청한 리소스 소유자`를 함께 검증하세요.",
        "owner": "백엔드 API 담당 개발자",
        "verify": "일반 사용자 계정으로 본인 ID는 조회되고, 다른 사용자 ID는 403 또는 404가 반환되는지 확인하세요.",
    },
}


PATTERN_GROUPS: list[tuple[str, list[tuple[str, re.Pattern[str], str]]]] = [
    ("secrets", [
        ("하드코딩된 API 키", re.compile(r'api[_-]?key\s*[=:]\s*["\'][^"\']{8,}["\']', re.IGNORECASE), "HIGH"),
        ("하드코딩된 비밀번호", re.compile(r'password\s*[=:]\s*["\'][^"\']{4,}["\']', re.IGNORECASE), "HIGH"),
        ("하드코딩된 시크릿", re.compile(r'secret\s*[=:]\s*["\'][^"\']{8,}["\']', re.IGNORECASE), "HIGH"),
        ("AWS Access Key", re.compile(r'AKIA[0-9A-Z]{16}'), "CRITICAL"),
        ("AWS Secret Key", re.compile(r'aws[_-]?secret\s*[=:]\s*["\'][^"\']{20,}["\']', re.IGNORECASE), "CRITICAL"),
        ("하드코딩된 토큰", re.compile(r'token\s*[=:]\s*["\'][^"\']{16,}["\']', re.IGNORECASE), "MEDIUM"),
        ("하드코딩된 DB URL", re.compile(r'(mysql|postgres|mongodb|redis)\:\/\/\w+:[^@\s]+@', re.IGNORECASE), "HIGH"),
        ("Private Key 블록", re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'), "CRITICAL"),
    ]),
    ("injection", [
        ("SQL Injection 가능성 (문자열 보간)", re.compile(r'query\s*\(\s*[f`"\'].*?\$\{?[^}]+\}?.*?(WHERE|SELECT|INSERT|UPDATE|DELETE)', re.IGNORECASE), "HIGH"),
        ("SQL Injection 가능성 (포맷 문자열)", re.compile(r'f["\'].*?(SELECT|INSERT|UPDATE|DELETE).*?\{', re.IGNORECASE), "HIGH"),
        ("eval() 사용", re.compile(r'\beval\s*\('), "HIGH"),
        ("exec() 사용 (Python)", re.compile(r'\bexec\s*\(\s*[^)]*input', re.IGNORECASE), "HIGH"),
        ("Command Injection 가능성", re.compile(r'(exec|spawn|system|Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\([^)]*(req\.|input|params|query|body|argv)', re.IGNORECASE), "CRITICAL"),
        ("SSRF 가능성", re.compile(r'(axios|get|post|fetch|requests\.(get|post)|httpx\.(get|post)|urllib\.request)\s*\([^)]*(req\.(body|query|params)|input|url)', re.IGNORECASE), "HIGH"),
    ]),
    ("auth", [
        ("CORS 전체 허용", re.compile(r'cors\s*\(\s*\{[^}]*origin\s*:\s*["\']?\*["\']?', re.IGNORECASE), "MEDIUM"),
        ("JWT localStorage 저장", re.compile(r'localStorage\.setItem\s*\([^)]*token', re.IGNORECASE), "MEDIUM"),
        ("인증 없는 admin 라우트", re.compile(r'(app|router)\.(get|post|put|delete)\s*\(["\']\/admin', re.IGNORECASE), "HIGH"),
        ("jwt.decode 사용 (검증 없음)", re.compile(r'jwt\.decode\s*\(', re.IGNORECASE), "HIGH"),
        ("응답에 password 필드 포함", re.compile(r'(res|response)\.(json|send)\s*\(\s*(await\s+)?\w*(user|member|account)\b(?!.*select)', re.IGNORECASE), "MEDIUM"),
        ("시큐어 쿠키 설정 누락 가능성", re.compile(r'res\.cookie\s*\([^)]*(token|session)(?![^)]*(httpOnly|secure|sameSite))', re.IGNORECASE), "HIGH"),
    ]),
    ("errors", [
        ("에러 스택 트레이스 노출", re.compile(r'(res|response)\.(json|send)\s*\([^)]*\bstack\b', re.IGNORECASE), "HIGH"),
        ("에러 메시지 직접 노출", re.compile(r'(res|response)\.(json|send)\s*\([^)]*err(or)?\.message', re.IGNORECASE), "MEDIUM"),
        ("민감 정보 로그 (Java)", re.compile(r'log\.(info|debug|warn)\s*\([^)]*password', re.IGNORECASE), "HIGH"),
        ("민감 정보 로그 (Python)", re.compile(r'(logger|logging)\.(info|debug|warning)\s*\([^)]*password', re.IGNORECASE), "HIGH"),
        ("console.log 민감 정보 출력", re.compile(r'console\.log\s*\(.*?(password|token|secret|key|user|auth)', re.IGNORECASE), "MEDIUM"),
        ("console.log 객체 전체 출력", re.compile(r'console\.log\s*\(\s*(JSON\.stringify|req\.|res\.|user|member)', re.IGNORECASE), "LOW"),
        ("print 민감 정보 출력 (Python)", re.compile(r'print\s*\(.*?(password|token|secret|key)', re.IGNORECASE), "MEDIUM"),
    ]),
    ("abuse", [
        ("로그인 라우트 Rate Limit 미적용 가능성", re.compile(r'(app|router)\.(post)\s*\(["\'].*(login|signin|auth)["\'](?!.*limit)', re.IGNORECASE), "MEDIUM"),
        ("비밀번호 재설정 Rate Limit 미적용 가능성", re.compile(r'(app|router)\.(post)\s*\(["\'].*(password|reset|forgot)["\'](?!.*limit)', re.IGNORECASE), "MEDIUM"),
        ("파일 확장자 검증 없는 업로드", re.compile(r'(multer|upload|diskStorage|Formidable)\s*\([^)]*\)', re.IGNORECASE), "MEDIUM"),
        ("파일명 직접 사용", re.compile(r'(writeFile|createWriteStream|open)\s*\([^)]*req\.(body|file|files)', re.IGNORECASE), "HIGH"),
        ("경로 탈출 가능성", re.compile(r'path\.(join|resolve)\s*\([^)]*req\.(body|params|query)', re.IGNORECASE), "HIGH"),
        ("소유자 검증 없는 단건 조회 가능성", re.compile(r'find(ById|_by_id)?\s*\(\s*req\.(params|query|body)\.id\s*\)', re.IGNORECASE), "MEDIUM"),
        ("소유자 검증 없는 단건 조회 가능성 (JPA)", re.compile(r'findById\s*\(\s*(id|userId|resourceId)\s*\)(?!.*UserId|.*owner)', re.IGNORECASE), "MEDIUM"),
    ]),
    ("config", [
        ("디버그 모드 활성화", re.compile(r'(debug\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True|DEBUG\s*[:=]\s*true)', re.IGNORECASE), "HIGH"),
    ]),
]


def _is_test_file(path: Path) -> bool:
    name = path.name.lower()
    parts = [p.lower() for p in path.parts]
    return (
        "test" in parts or "tests" in parts or "__tests__" in parts
        or name.endswith((".test.ts", ".test.js", ".spec.ts", ".spec.js", "_test.py"))
        or "test" in name
    )


def _safe_read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _collect_files(base: Path, skip_test_files: bool) -> list[Path]:
    files: list[Path] = []
    for file in base.rglob("*"):
        if not file.is_file():
            continue
        if any(part in SKIP_DIRS for part in file.parts):
            continue
        if file.suffix.lower() not in CODE_EXTENSIONS | TEXT_CONFIG_EXTENSIONS:
            continue
        if skip_test_files and _is_test_file(file):
            continue
        files.append(file)
    return files


def _detect_frameworks(base: Path) -> list[str]:
    detected: set[str] = set()
    for framework, filenames in FRAMEWORK_HINTS.items():
        for filename in filenames:
            if (base / filename).exists():
                detected.add(framework)

    package_json = base / "package.json"
    if package_json.exists():
        try:
            data = json.loads(_safe_read(package_json) or "{}")
            deps = set((data.get("dependencies") or {}).keys()) | set((data.get("devDependencies") or {}).keys())
        except json.JSONDecodeError:
            deps = set()
        mapping = {
            "next": "next.js",
            "react": "react",
            "vue": "vue",
            "nuxt": "nuxt",
            "svelte": "svelte",
            "express": "express",
            "nestjs": "nestjs",
            "@nestjs/core": "nestjs",
            "fastify": "fastify",
            "laravel/framework": "laravel",
        }
        for dep, framework in mapping.items():
            if dep in deps:
                detected.add(framework)

    pyproject = _safe_read(base / "pyproject.toml")
    requirements = _safe_read(base / "requirements.txt")
    pipfile = _safe_read(base / "Pipfile")
    python_meta = "\n".join([pyproject, requirements, pipfile]).lower()
    for dep, framework in {
        "django": "django",
        "flask": "flask",
        "fastapi": "fastapi",
    }.items():
        if dep in python_meta:
            detected.add(framework)

    if (base / "pom.xml").exists():
        pom = _safe_read(base / "pom.xml").lower()
        if "spring-boot" in pom:
            detected.add("spring boot")

    return sorted(detected)


def _scan_patterns(files: list[Path], group_name: str, patterns: list[tuple[str, re.Pattern[str], str]]) -> list[dict]:
    findings: list[dict] = []
    for file in files:
        content = _safe_read(file)
        if not content:
            continue
        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            for label, pattern, severity in patterns:
                if not pattern.search(line):
                    continue
                if _should_ignore_match(line, label):
                    continue
                findings.append({
                    "group": group_name,
                    "severity": severity,
                    "label": label,
                    "file": str(file),
                    "line": lineno,
                    "snippet": line.strip()[:160],
                })
    return findings


def _should_ignore_match(line: str, label: str) -> bool:
    stripped = line.strip()
    if "re.compile(" in stripped:
        return True
    if stripped == f'"{label}": {{' or stripped == f"'{label}': {{":
        return True
    internal_markers = ['"risk":', '"attack":', '"fix":', '"snippet":', '"label":', '"line": _find_line_number']
    if any(marker in stripped for marker in internal_markers):
        return True
    if "_http_fetch(" in stripped and label in {"SSRF 가능성", "Command Injection 가능성"}:
        return True
    return False


def _check_env_gitignore(base: Path) -> list[dict]:
    findings: list[dict] = []
    gitignore_path = base / ".gitignore"
    if not gitignore_path.exists():
        findings.append({
            "group": "config",
            "severity": "HIGH",
            "label": ".gitignore 파일 없음",
            "file": str(base),
            "line": 0,
            "snippet": ".gitignore가 없으면 .env 파일이 저장소에 포함될 수 있습니다.",
        })
        return findings

    gitignore_content = _safe_read(gitignore_path)
    for env_file in ENV_GITIGNORE_FILES:
        if (base / env_file).exists() and env_file not in gitignore_content:
            findings.append({
                "group": "config",
                "severity": "HIGH",
                "label": f".env 파일이 .gitignore에 없음 ({env_file})",
                "file": str(gitignore_path),
                "line": 0,
                "snippet": f"{env_file}이 존재하지만 .gitignore에 누락되어 있습니다.",
            })
    return findings


def _check_missing_security_headers(files: list[Path]) -> list[dict]:
    js_like = [f for f in files if f.suffix.lower() in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}]
    findings: list[dict] = []
    for file in js_like:
        content = _safe_read(file)
        if "express()" not in content and "fastify(" not in content and "NestFactory.create" not in content:
            continue
        if "helmet(" in content or "contentSecurityPolicy" in content:
            continue
        findings.append({
            "group": "config",
            "severity": "MEDIUM",
            "label": "보안 헤더 설정 부재 가능성",
            "file": str(file),
            "line": 0,
            "snippet": "Node 서버 코드에서 보안 헤더 미들웨어가 보이지 않습니다.",
        })
    return findings


def _check_framework_specific_risks(base: Path, files: list[Path], frameworks: list[str]) -> list[dict]:
    findings: list[dict] = []

    if "django" in frameworks:
        for file in files:
            if file.name not in {"settings.py", "settings_prod.py", "settings_base.py"} and "settings" not in file.parts:
                continue
            content = _safe_read(file)
            if re.search(r"DEBUG\s*=\s*True", content):
                findings.append({
                    "group": "framework",
                    "severity": "CRITICAL",
                    "label": "Django DEBUG 활성화",
                    "file": str(file),
                    "line": _find_line_number(content, "DEBUG"),
                    "snippet": "DEBUG = True",
                })
            if re.search(r"ALLOWED_HOSTS\s*=\s*\[[^\]]*['\"]\*['\"]", content):
                findings.append({
                    "group": "framework",
                    "severity": "HIGH",
                    "label": "Django ALLOWED_HOSTS 전체 허용 가능성",
                    "file": str(file),
                    "line": _find_line_number(content, "ALLOWED_HOSTS"),
                    "snippet": "ALLOWED_HOSTS includes '*'",
                })

    if "flask" in frameworks:
        for file in files:
            if file.suffix.lower() != ".py":
                continue
            content = _safe_read(file)
            if re.search(r"app\.run\s*\([^)]*debug\s*=\s*True", content):
                findings.append({
                    "group": "framework",
                    "severity": "CRITICAL",
                    "label": "Flask DEBUG 활성화",
                    "file": str(file),
                    "line": _find_line_number(content, "debug=True"),
                    "snippet": "app.run(..., debug=True)",
                })

    if "fastapi" in frameworks:
        for file in files:
            if file.suffix.lower() != ".py":
                continue
            content = _safe_read(file)
            if "FastAPI(" not in content:
                continue
            if "TrustedHostMiddleware" not in content:
                findings.append({
                    "group": "framework",
                    "severity": "MEDIUM",
                    "label": "FastAPI TrustedHostMiddleware 부재 가능성",
                    "file": str(file),
                    "line": _find_line_number(content, "FastAPI("),
                    "snippet": "FastAPI app found without TrustedHostMiddleware",
                })

    if "spring" in frameworks or "spring boot" in frameworks:
        for file in files:
            if file.suffix.lower() not in {".java", ".kt", ".kts"}:
                continue
            content = _safe_read(file)
            if ".csrf(" in content and "disable" in content:
                findings.append({
                    "group": "framework",
                    "severity": "HIGH",
                    "label": "Spring Security CSRF 비활성화",
                    "file": str(file),
                    "line": _find_line_number(content, "csrf"),
                    "snippet": ".csrf(...disable())",
                })
            if "permitAll()" in content:
                findings.append({
                    "group": "framework",
                    "severity": "MEDIUM",
                    "label": "Spring permitAll 과다 사용 가능성",
                    "file": str(file),
                    "line": _find_line_number(content, "permitAll"),
                    "snippet": "permitAll() used in security config",
                })
            if "@CrossOrigin" in content and "*" in content:
                findings.append({
                    "group": "framework",
                    "severity": "MEDIUM",
                    "label": "Spring CORS 전체 허용",
                    "file": str(file),
                    "line": _find_line_number(content, "@CrossOrigin"),
                    "snippet": "@CrossOrigin with wildcard origin",
                })

    if any(name in frameworks for name in {"next.js", "express", "nestjs", "fastify"}):
        findings.extend(_check_missing_security_headers(files))

    if "next.js" in frameworks:
        for file in files:
            if file.name not in {"next.config.js", "next.config.mjs", "next.config.ts"} and "next.config" not in file.name:
                continue
            content = _safe_read(file)
            if "NEXT_PUBLIC_" in content and re.search(r"(api|secret|token|key)", content, re.IGNORECASE):
                findings.append({
                    "group": "framework",
                    "severity": "HIGH",
                    "label": "Next.js 환경변수 공개 노출 가능성",
                    "file": str(file),
                    "line": _find_line_number(content, "NEXT_PUBLIC_"),
                    "snippet": "NEXT_PUBLIC_ variable appears in config",
                })
            if re.search(r"(remotePatterns|domains)\s*:\s*\[[^\]]*['\"]\*['\"]", content):
                findings.append({
                    "group": "framework",
                    "severity": "MEDIUM",
                    "label": "Next.js 이미지 원격 도메인 전체 허용 가능성",
                    "file": str(file),
                    "line": _find_line_number(content, "remotePatterns"),
                    "snippet": "next/image remote domain configuration is too broad",
                })

    if "nestjs" in frameworks:
        for file in files:
            if file.suffix.lower() not in {".ts", ".js"}:
                continue
            content = _safe_read(file)
            if "NestFactory.create" not in content:
                continue
            if "ValidationPipe" not in content:
                findings.append({
                    "group": "framework",
                    "severity": "MEDIUM",
                    "label": "NestJS ValidationPipe 부재 가능성",
                    "file": str(file),
                    "line": _find_line_number(content, "NestFactory.create"),
                    "snippet": "Nest application bootstraps without ValidationPipe",
                })

    if "rails" in frameworks:
        force_ssl_checked = False
        for file in files:
            if file.name == "production.rb":
                force_ssl_checked = True
                content = _safe_read(file)
                if "force_ssl = true" not in content:
                    findings.append({
                        "group": "framework",
                        "severity": "HIGH",
                        "label": "Rails force_ssl 비활성 가능성",
                        "file": str(file),
                        "line": _find_line_number(content, "force_ssl"),
                        "snippet": "production.rb without force_ssl = true",
                    })
            if file.suffix.lower() != ".rb":
                continue
            content = _safe_read(file)
            if "skip_forgery_protection" in content:
                findings.append({
                    "group": "framework",
                    "severity": "HIGH",
                    "label": "Rails forgery protection 비활성화",
                    "file": str(file),
                    "line": _find_line_number(content, "skip_forgery_protection"),
                    "snippet": "skip_forgery_protection used",
                })
        if not force_ssl_checked and (base / "config/environments/production.rb").exists():
            content = _safe_read(base / "config/environments/production.rb")
            if "force_ssl = true" not in content:
                findings.append({
                    "group": "framework",
                    "severity": "HIGH",
                    "label": "Rails force_ssl 비활성 가능성",
                    "file": str(base / "config/environments/production.rb"),
                    "line": _find_line_number(content, "force_ssl"),
                    "snippet": "production.rb without force_ssl = true",
                })

    if "laravel" in frameworks:
        env_file = base / ".env"
        if env_file.exists():
            content = _safe_read(env_file)
            if re.search(r"APP_DEBUG\s*=\s*true", content, re.IGNORECASE):
                findings.append({
                    "group": "framework",
                    "severity": "CRITICAL",
                    "label": "Laravel APP_DEBUG 활성화",
                    "file": str(env_file),
                    "line": _find_line_number(content, "APP_DEBUG"),
                    "snippet": "APP_DEBUG=true",
                })
            if re.search(r"APP_KEY\s*=\s*$", content, re.MULTILINE):
                findings.append({
                    "group": "framework",
                    "severity": "HIGH",
                    "label": "Laravel APP_KEY 누락 가능성",
                    "file": str(env_file),
                    "line": _find_line_number(content, "APP_KEY"),
                    "snippet": "APP_KEY is empty",
                })

    return findings


def _find_line_number(content: str, token: str) -> int:
    for index, line in enumerate(content.splitlines(), start=1):
        if token in line:
            return index
    return 0


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
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    return result.stdout or result.stderr


def _summarize_npm_audit(raw: str) -> dict | None:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    vulns = (data.get("metadata") or {}).get("vulnerabilities") or {}
    if not isinstance(vulns, dict):
        return None
    total = sum(vulns.values())
    return {"total": total, "by_severity": {k: v for k, v in vulns.items() if v}}


def _deduplicate_findings(findings: list[dict]) -> list[dict]:
    seen: set[tuple[str, str, int, str]] = set()
    deduped: list[dict] = []
    for finding in findings:
        key = (finding["label"], finding["file"], finding["line"], finding["snippet"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _build_finding_detail(finding: dict) -> str:
    definition = ISSUE_DEFINITIONS.get(finding["label"], {})
    category = definition.get("category", "일반 보안 이슈")
    loc = f"{finding['file']}:{finding['line']}" if finding["line"] else finding["file"]
    return "\n".join([
        f"- 이슈: {finding['label']} [{finding['severity']}]",
        f"  분류: {category}",
        f"  위치: {loc}",
        f"  코드: {finding['snippet']}",
        f"  왜 위험한가: {definition.get('risk', '공격 표면이 넓어질 수 있습니다.')}",
        f"  공격자 시나리오: {definition.get('attack', '공격자가 이 동작을 악용해 권한 없는 접근을 시도할 수 있습니다.')}",
    ])


def _format_findings_for_people(findings: list[dict]) -> str:
    if not findings:
        return "발견된 이슈 없음"
    return "\n\n".join(_build_finding_detail(finding) for finding in findings)


def _format_priority_actions(findings: list[dict]) -> str:
    if not findings:
        return "1. 현재 스캔 기준 즉시 막아야 할 치명적 이슈는 발견되지 않았습니다.\n2. 그래도 인증, 권한, 배포 설정은 수동 검토가 필요합니다."

    labels = [finding["label"] for finding in findings]
    top_labels = Counter(labels).most_common(5)
    actions: list[str] = []
    for index, (label, _) in enumerate(top_labels, start=1):
        definition = ISSUE_DEFINITIONS.get(label, {})
        actions.append(f"{index}. {label}: {definition.get('fix', '해당 코드와 설정을 검토하세요.')}")
    return "\n".join(actions)


def _calculate_release_decision(findings: list[dict]) -> tuple[str, str]:
    critical = sum(1 for finding in findings if finding["severity"] == "CRITICAL")
    high = sum(1 for finding in findings if finding["severity"] == "HIGH")
    medium = sum(1 for finding in findings if finding["severity"] == "MEDIUM")

    if critical or high:
        return (
            "출시 차단",
            "치명적이거나 높은 위험 이슈가 있어 수정 전 배포를 멈춰야 합니다.",
        )
    if medium >= 3:
        return (
            "수정 후 재점검",
            "즉시 뚫린다고 단정할 정도는 아니지만, 중간 위험 이슈가 누적되어 배포 전 재점검이 필요합니다.",
        )
    return (
        "기본 점검 통과",
        "현재 스캔 기준 즉시 차단급 이슈는 없지만, 인증/권한/배포 환경은 별도 검증이 필요합니다.",
    )


def _format_release_checklist(findings: list[dict]) -> str:
    labels = {finding["label"] for finding in findings}
    checklist = [
        ("비밀키/DB 비밀번호 제거", any("하드코딩" in label or "AWS" in label or "Private Key" in label for label in labels)),
        ("관리자/사용자 데이터 권한 검증", any("admin" in label or "소유자 검증" in label or "permitAll" in label for label in labels)),
        ("로그인/재설정 남용 방지", any("Rate Limit" in label for label in labels)),
        ("브라우저 보호 설정", any("CORS" in label or "쿠키" in label or "보안 헤더" in label or "CSRF" in label for label in labels)),
        ("운영 설정 점검", any("DEBUG" in label or ".gitignore" in label or "TrustedHost" in label or "ALLOWED_HOSTS" in label for label in labels)),
    ]
    lines = []
    for index, (title, flagged) in enumerate(checklist, start=1):
        status = "점검 필요" if flagged else "기본 통과"
        lines.append(f"{index}. {title}: {status}")
    return "\n".join(lines)


def _format_coverage_note(frameworks: list[str]) -> str:
    framework_text = ", ".join(frameworks) if frameworks else "특정 프레임워크를 식별하지 못함"
    return "\n".join([
        f"- 감지된 프레임워크/런타임 힌트: {framework_text}",
        "- 이 도구는 정적 패턴 기반 1차 점검기라서, 권한 모델, 비즈니스 로직, 실제 배포 설정, WAF/인프라 정책은 완전하게 증명하지 못합니다.",
        "- 모든 프레임워크를 100% 검증한다고 말할 수는 없습니다. 대신 프레임워크 비의존 공통 취약점과 대표 설정 실수를 넓게 잡는 방향으로 확장해야 합니다.",
        "- 출시 직전에는 실제 인증 흐름, 관리자 기능, 결제/업로드/웹훅 엔드포인트에 대한 동적 테스트가 추가로 필요합니다.",
    ])


def _build_live_finding(label: str, severity: str, detail: str) -> dict:
    return {
        "group": "live",
        "severity": severity,
        "label": label,
        "file": "live-service",
        "line": 0,
        "snippet": detail,
    }


def _build_request_headers(
    extra_headers: dict[str, str] | None = None,
    bearer_token: str | None = None,
    session_cookie: str | None = None,
) -> dict[str, str]:
    headers = {
        "User-Agent": "security-check-mcp/0.1",
        "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
    }
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    if session_cookie:
        headers["Cookie"] = session_cookie
    if extra_headers:
        headers.update(extra_headers)
    return headers


def _http_fetch(
    url: str,
    method: str = "GET",
    timeout_seconds: int = 10,
    extra_headers: dict[str, str] | None = None,
    bearer_token: str | None = None,
    session_cookie: str | None = None,
) -> tuple[int, dict[str, str], list[tuple[str, str]], str] | tuple[None, None, None, str]:
    request = Request(
        url,
        headers=_build_request_headers(
            extra_headers=extra_headers,
            bearer_token=bearer_token,
            session_cookie=session_cookie,
        ),
        method=method,
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return (
                getattr(response, "status", 200),
                dict(response.headers.items()),
                list(response.headers.items()),
                response.read(4096).decode("utf-8", errors="ignore"),
            )
    except HTTPError as exc:
        return (
            exc.code,
            dict(exc.headers.items()),
            list(exc.headers.items()),
            exc.read(4096).decode("utf-8", errors="ignore"),
        )
    except URLError as exc:
        return None, None, None, str(exc.reason)


def analyze_live_service(target_url: str, timeout_seconds: int = 10) -> str:
    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return f"오류: 유효한 URL이 아닙니다 - {target_url}"

    status_code, headers, header_items, body = _http_fetch(target_url, method="GET", timeout_seconds=timeout_seconds)
    if status_code is None or headers is None or header_items is None:
        return f"오류: 라이브 서비스에 연결하지 못했습니다 - {body}"

    findings: list[dict] = []
    csp = headers.get("Content-Security-Policy", "")
    xfo = headers.get("X-Frame-Options", "")
    xcto = headers.get("X-Content-Type-Options", "")
    aco = headers.get("Access-Control-Allow-Origin", "")
    hsts = headers.get("Strict-Transport-Security", "")
    server = headers.get("Server", "") or headers.get("X-Powered-By", "")
    set_cookie_headers = response_headers_get_all(header_items, "Set-Cookie")
    body_lower = body.lower()

    if aco.strip() == "*":
        findings.append(_build_live_finding("라이브 서비스 CORS 전체 허용", "HIGH", "Access-Control-Allow-Origin: *"))
    if not csp:
        findings.append(_build_live_finding("라이브 서비스 CSP 헤더 누락", "MEDIUM", "Content-Security-Policy header missing"))
    if not xfo and "frame-ancestors" not in csp.lower():
        findings.append(_build_live_finding("라이브 서비스 클릭재킹 방어 누락", "MEDIUM", "X-Frame-Options and frame-ancestors missing"))
    if xcto.lower() != "nosniff":
        findings.append(_build_live_finding("라이브 서비스 MIME 스니핑 방어 누락", "LOW", f"X-Content-Type-Options: {xcto or 'missing'}"))
    if parsed.scheme == "https" and not hsts:
        findings.append(_build_live_finding("라이브 서비스 HSTS 누락", "MEDIUM", "Strict-Transport-Security header missing"))
    if server:
        findings.append(_build_live_finding("라이브 서비스 서버 배너 노출", "LOW", server))
    if any(token in body_lower for token in ["traceback", "stack trace", "whitelabel error page", "exception at", "debugger"]):
        findings.append(_build_live_finding("라이브 서비스 에러 페이지 노출", "HIGH", "response body looks like a framework error page"))

    for cookie in set_cookie_headers:
        lower_cookie = cookie.lower()
        if any(token in lower_cookie for token in ["session", "token", "auth", "jwt"]):
            missing = [flag for flag in ["httponly", "secure", "samesite"] if flag not in lower_cookie]
            if missing:
                findings.append(_build_live_finding(
                    "라이브 서비스 세션 쿠키 보호 속성 누락",
                    "HIGH" if "httponly" in missing or "secure" in missing else "MEDIUM",
                    f"missing cookie attributes: {', '.join(missing)}",
                ))

    findings = _deduplicate_findings(findings)
    findings.sort(key=lambda item: (-SEVERITY_ORDER.get(item["severity"], 0), item["label"]))
    severity_counter = Counter(finding["severity"] for finding in findings)
    release_status, release_reason = _calculate_release_decision(findings)

    sections = [
        "# 라이브 서비스 보안 점검 리포트",
        f"- 점검 URL: {target_url}",
        f"- HTTP 상태 코드: {status_code}",
        f"- 감지 이슈 수: CRITICAL={severity_counter.get('CRITICAL', 0)}, HIGH={severity_counter.get('HIGH', 0)}, MEDIUM={severity_counter.get('MEDIUM', 0)}, LOW={severity_counter.get('LOW', 0)}",
        f"- 출시 판정: {release_status}",
        "",
        "## 한눈에 보기",
        release_reason,
        "",
        "## 헤더/쿠키 점검 결과",
        _format_findings_for_people(findings) if findings else "발견된 이슈 없음",
        "",
        "## 공격자 관점 평가",
        "라이브 응답에서 보이는 헤더, 쿠키, 에러 페이지는 공격자도 동일하게 볼 수 있습니다.",
        "즉, 여기서 나온 문제는 '실제 운영 표면'에 이미 드러나 있을 가능성이 높습니다.",
    ]
    return "\n".join(sections).strip()


def response_headers_get_all(headers: list[tuple[str, str]], target_name: str) -> list[str]:
    values: list[str] = []
    for name, value in headers:
        if name.lower() == target_name.lower():
            values.append(value)
    return values


def _normalize_probe_headers(raw_headers: str | None) -> dict[str, str]:
    if not raw_headers:
        return {}
    normalized: dict[str, str] = {}
    for chunk in raw_headers.splitlines():
        if ":" not in chunk:
            continue
        name, value = chunk.split(":", 1)
        name = name.strip()
        value = value.strip()
        if name and value:
            normalized[name] = value
    return normalized


def analyze_attack_surface(target_url: str, timeout_seconds: int = 10) -> str:
    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return f"오류: 유효한 URL이 아닙니다 - {target_url}"

    base = f"{parsed.scheme}://{parsed.netloc}"
    candidate_paths = [
        "/admin",
        "/dashboard",
        "/manage",
        "/api/admin",
        "/login",
        "/signin",
        "/forgot-password",
        "/reset-password",
        "/swagger",
        "/openapi.json",
        "/actuator/health",
        "/health",
        "/users/1",
        "/orders/1",
    ]
    findings: list[dict] = []
    probed: list[str] = []
    connection_errors = 0

    for path in candidate_paths:
        status_code, headers, _, body = _http_fetch(f"{base}{path}", method="GET", timeout_seconds=timeout_seconds)
        if status_code is None or headers is None:
            connection_errors += 1
            continue
        probed.append(f"{path} -> {status_code}")
        lower_body = body.lower()

        if path in {"/admin", "/dashboard", "/manage", "/api/admin"} and status_code == 200:
            findings.append(_build_live_finding("관리자 경로 무인증 노출 가능성", "CRITICAL", f"{path} returned 200 without auth"))
        if path in {"/login", "/signin", "/forgot-password", "/reset-password", "/swagger", "/openapi.json", "/actuator/health", "/health"} and status_code == 200:
            severity = "MEDIUM" if path in {"/health", "/actuator/health"} else "LOW"
            findings.append(_build_live_finding("민감 엔드포인트 공개 노출 가능성", severity, f"{path} returned 200"))
        if path in {"/users/1", "/orders/1"} and status_code == 200:
            if any(token in lower_body for token in ["email", "user", "order", "id", "{", "["]):
                findings.append(_build_live_finding("순차 ID 기반 데이터 노출 가능성", "HIGH", f"{path} returned data-like response"))

    options_status, options_headers, _, _ = _http_fetch(base, method="OPTIONS", timeout_seconds=timeout_seconds)
    if options_status is not None and options_headers is not None:
        allow_header = options_headers.get("Allow", "")
        if any(method in allow_header.upper() for method in ["PUT", "DELETE", "PATCH", "TRACE"]):
            findings.append(_build_live_finding("위험한 HTTP 메서드 노출 가능성", "MEDIUM", f"Allow: {allow_header}"))
    else:
        connection_errors += 1

    if not probed and connection_errors:
        return f"오류: 공격 표면 점검을 수행하지 못했습니다 - {target_url} 에 연결할 수 없습니다."

    findings = _deduplicate_findings(findings)
    findings.sort(key=lambda item: (-SEVERITY_ORDER.get(item["severity"], 0), item["label"]))
    severity_counter = Counter(finding["severity"] for finding in findings)
    release_status, release_reason = _calculate_release_decision(findings)

    sections = [
        "# 공격 표면 점검 리포트",
        f"- 점검 URL: {target_url}",
        f"- 시도한 경로 수: {len(probed)}개",
        f"- 감지 이슈 수: CRITICAL={severity_counter.get('CRITICAL', 0)}, HIGH={severity_counter.get('HIGH', 0)}, MEDIUM={severity_counter.get('MEDIUM', 0)}, LOW={severity_counter.get('LOW', 0)}",
        f"- 출시 판정: {release_status}",
        "",
        "## 한눈에 보기",
        release_reason,
        "",
        "## 공격자가 먼저 눌러볼 경로",
        "\n".join(f"- {entry}" for entry in probed) if probed else "- 응답을 확인한 경로가 없습니다.",
        "",
        "## 발견된 공격 표면",
        _format_findings_for_people(findings) if findings else "발견된 이슈 없음",
        "",
        "## 주의",
        "이 점검은 공개 경로 탐색 기반의 얕은 동적 검사입니다.",
        "실제 인증 우회, CSRF, IDOR 증명까지 하려면 테스트 계정과 시나리오 기반 점검이 추가로 필요합니다.",
    ]
    return "\n".join(sections).strip()


def analyze_authenticated_flows(
    target_url: str,
    bearer_token: str | None = None,
    session_cookie: str | None = None,
    extra_headers: str | None = None,
    reference_user_id: str = "1",
    alternate_user_id: str = "2",
    timeout_seconds: int = 10,
) -> str:
    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return f"오류: 유효한 URL이 아닙니다 - {target_url}"
    if not bearer_token and not session_cookie and not extra_headers:
        return "오류: 인증 기반 점검에는 bearer_token, session_cookie, extra_headers 중 하나가 필요합니다."

    base = f"{parsed.scheme}://{parsed.netloc}"
    manual_headers = _normalize_probe_headers(extra_headers)
    findings: list[dict] = []
    probed: list[str] = []

    admin_paths = ["/admin", "/dashboard", "/manage", "/api/admin"]
    for path in admin_paths:
        status_code, _, _, body = _http_fetch(
            f"{base}{path}",
            method="GET",
            timeout_seconds=timeout_seconds,
            extra_headers=manual_headers,
            bearer_token=bearer_token,
            session_cookie=session_cookie,
        )
        if status_code is None:
            continue
        probed.append(f"{path} -> {status_code}")
        if status_code == 200:
            findings.append(_build_live_finding("일반 사용자로 관리자 경로 접근 가능성", "CRITICAL", f"{path} returned 200 with provided auth context"))
        elif status_code not in {401, 403, 404} and "admin" in body.lower():
            findings.append(_build_live_finding("일반 사용자로 관리자 경로 접근 가능성", "HIGH", f"{path} returned {status_code} and body suggests admin content"))

    resource_templates = ["/users/{id}", "/orders/{id}", "/profiles/{id}", "/accounts/{id}"]
    for template in resource_templates:
        own_path = template.format(id=reference_user_id)
        other_path = template.format(id=alternate_user_id)
        own_status, _, _, own_body = _http_fetch(
            f"{base}{own_path}",
            method="GET",
            timeout_seconds=timeout_seconds,
            extra_headers=manual_headers,
            bearer_token=bearer_token,
            session_cookie=session_cookie,
        )
        other_status, _, _, other_body = _http_fetch(
            f"{base}{other_path}",
            method="GET",
            timeout_seconds=timeout_seconds,
            extra_headers=manual_headers,
            bearer_token=bearer_token,
            session_cookie=session_cookie,
        )
        if own_status is None or other_status is None:
            continue
        probed.append(f"{own_path} -> {own_status}")
        probed.append(f"{other_path} -> {other_status}")
        own_text = own_body.strip()
        other_text = other_body.strip()
        if own_status == 200 and other_status == 200 and other_text and own_text != other_text:
            findings.append(_build_live_finding(
                "인증 상태 IDOR 가능성",
                "CRITICAL",
                f"{own_path} and {other_path} both returned 200 with different bodies",
            ))
        elif other_status == 200 and any(token in other_text.lower() for token in ["email", "name", "order", "user", "{", "["]):
            findings.append(_build_live_finding(
                "인증 상태 IDOR 가능성",
                "HIGH",
                f"{other_path} returned data-like response with provided auth context",
            ))

    if not probed:
        return f"오류: 인증 기반 점검을 수행하지 못했습니다 - {target_url} 에서 응답을 확인할 수 없습니다."

    findings = _deduplicate_findings(findings)
    findings.sort(key=lambda item: (-SEVERITY_ORDER.get(item["severity"], 0), item["label"]))
    severity_counter = Counter(finding["severity"] for finding in findings)
    release_status, release_reason = _calculate_release_decision(findings)

    sections = [
        "# 인증 기반 권한 점검 리포트",
        f"- 점검 URL: {target_url}",
        f"- 기준 사용자 ID: {reference_user_id}",
        f"- 비교 사용자 ID: {alternate_user_id}",
        f"- 감지 이슈 수: CRITICAL={severity_counter.get('CRITICAL', 0)}, HIGH={severity_counter.get('HIGH', 0)}, MEDIUM={severity_counter.get('MEDIUM', 0)}, LOW={severity_counter.get('LOW', 0)}",
        f"- 출시 판정: {release_status}",
        "",
        "## 한눈에 보기",
        release_reason,
        "",
        "## 실제로 시도한 권한 검증 경로",
        "\n".join(f"- {entry}" for entry in probed),
        "",
        "## 발견된 권한 문제",
        _format_findings_for_people(findings) if findings else "발견된 이슈 없음",
        "",
        "## 주의",
        "이 점검은 제공된 인증 정보가 일반 사용자 권한이라는 가정 아래 동작합니다.",
        "관리자 토큰을 넣으면 결과가 왜곡되므로, 반드시 일반 사용자 계정으로 점검해야 합니다.",
    ]
    return "\n".join(sections).strip()


def analyze_project(base_path: str, skip_test_files: bool = True) -> str:
    base = Path(base_path)
    if not base.exists():
        return f"오류: 경로가 존재하지 않습니다 - {base_path}"

    files = _collect_files(base, skip_test_files=skip_test_files)
    frameworks = _detect_frameworks(base)

    findings: list[dict] = []
    for group_name, patterns in PATTERN_GROUPS:
        findings.extend(_scan_patterns(files, group_name, patterns))
    findings.extend(_check_env_gitignore(base))
    findings.extend(_check_framework_specific_risks(base, files, frameworks))
    findings = _deduplicate_findings(findings)
    findings.sort(key=lambda item: (-SEVERITY_ORDER.get(item["severity"], 0), item["file"], item["line"]))

    severity_counter = Counter(finding["severity"] for finding in findings)
    release_blockers = [f for f in findings if f["severity"] in {"CRITICAL", "HIGH"}]
    release_status, release_reason = _calculate_release_decision(findings)
    npm_audit_raw = _run_npm_audit(base)
    npm_audit_summary = _summarize_npm_audit(npm_audit_raw) if npm_audit_raw else None

    sections = [
        f"# 보안 점검 리포트",
        f"- 점검 경로: {base_path}",
        f"- 스캔 파일 수: {len(files)}개",
        f"- 감지 이슈 수: CRITICAL={severity_counter.get('CRITICAL', 0)}, HIGH={severity_counter.get('HIGH', 0)}, MEDIUM={severity_counter.get('MEDIUM', 0)}, LOW={severity_counter.get('LOW', 0)}",
        f"- 출시 판정: {release_status}",
        "",
        "## 한눈에 보기",
        "이 리포트는 비개발자가 바로 판단할 수 있도록 어떤 문제가 있는지와 왜 위험한지를 보여줍니다.",
        release_reason,
        "",
        "## 출시 체크리스트",
        _format_release_checklist(findings),
        "",
        "## 주요 이슈 요약",
        "\n".join(
            f"{index}. {finding['label']} [{finding['severity']}]"
            for index, finding in enumerate((release_blockers or findings[:5]), start=1)
        ) if (release_blockers or findings[:5]) else "발견된 주요 이슈 없음",
        "",
    ]

    if release_blockers:
        sections.extend([
            "## 출시 전 반드시 막아야 하는 이슈",
            _format_findings_for_people(release_blockers[:15]),
            "",
        ])

    medium_low = [f for f in findings if f["severity"] in {"MEDIUM", "LOW"}]
    if medium_low:
        sections.extend([
            "## 추가 점검이 필요한 이슈",
            _format_findings_for_people(medium_low[:15]),
            "",
        ])

    if npm_audit_summary is not None:
        sections.append("## 의존성 취약점")
        if npm_audit_summary["total"] == 0:
            sections.append("- `npm audit` 기준 알려진 취약점은 없습니다.")
        else:
            severity_text = ", ".join(f"{k}={v}" for k, v in npm_audit_summary["by_severity"].items())
            sections.append(f"- `npm audit` 결과 총 {npm_audit_summary['total']}개 취약점이 확인됐습니다. ({severity_text})")
            sections.append("- 라이브러리 취약점은 코드가 안전해도 서비스가 뚫릴 수 있으므로 즉시 업데이트 계획이 필요합니다.")
        sections.append("")

    sections.extend([
        "## 공격자 관점 평가",
        "현재 방식만으로는 공격자가 문제를 못 찾을 정도로 충분하다고 보기 어렵습니다.",
        "이유는 패턴 기반 정적 분석만으로는 인증 우회, 권한 상승, CSRF, 실제 배포 설정 실수, 스토리지 공개, 관리자 기능 오남용 같은 핵심 공격면을 완전히 증명할 수 없기 때문입니다.",
        "",
        "## 커버리지와 한계",
        _format_coverage_note(frameworks),
    ])

    if not findings and npm_audit_summary is None:
        sections.extend([
            "",
            "## 결론",
            "정적 패턴 기준으로는 즉시 보이는 문제는 없었습니다. 다만 이것만으로 안전하다고 결론 내리면 안 됩니다.",
        ])

    return "\n".join(sections).strip()


def _resolve_path_for_write(raw_path: str) -> Path:
    return Path(raw_path).expanduser().resolve(strict=False)


def _is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
    except ValueError:
        return False
    return True


def export_report_to_file(
    report_content: str,
    output_path: str,
    overwrite: bool = False,
    allowed_base_path: str = "",
) -> str:
    if not report_content or not report_content.strip():
        return "오류: 저장할 리포트 내용이 비어 있습니다."
    if not output_path or not output_path.strip():
        return "오류: 저장할 파일 경로가 비어 있습니다."

    destination = _resolve_path_for_write(output_path)
    if allowed_base_path:
        allowed_base = _resolve_path_for_write(allowed_base_path)
        if not allowed_base.exists() or not allowed_base.is_dir():
            return f"오류: 허용된 workspace 경로가 유효하지 않습니다 - {allowed_base}"
        if not _is_relative_to(destination, allowed_base):
            return f"오류: 리포트는 허용된 workspace 내부에만 저장할 수 있습니다 - {allowed_base}"

    if destination.exists() and not overwrite:
        return f"오류: 파일이 이미 존재합니다 - {destination}"

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        content = report_content.rstrip() + "\n"
        destination.write_text(content, encoding="utf-8")
    except OSError as exc:
        return f"오류: 리포트를 저장하지 못했습니다 - {destination} ({exc})"

    return f"리포트 저장 완료: {destination}"


def register_security_tools(mcp: FastMCP) -> None:
    @mcp.tool()
    def check_security(base_path: str, skip_test_files: bool = True) -> str:
        """
        코드베이스를 정적 패턴 기반으로 보안 점검하고 비개발자도 이해할 수 있는 리포트를 반환한다.

        Parameters
        ----------
        base_path : str
            점검할 프로젝트 루트 디렉터리
        skip_test_files : bool
            True면 테스트 파일은 제외한다.
        """
        return analyze_project(base_path=base_path, skip_test_files=skip_test_files)

    @mcp.tool()
    def check_live_security(target_url: str, timeout_seconds: int = 10) -> str:
        """
        배포된 URL에 실제 요청을 보내 응답 헤더, 쿠키, 에러 노출을 점검한다.

        Parameters
        ----------
        target_url : str
            점검할 서비스 URL
        timeout_seconds : int
            요청 타임아웃
        """
        return analyze_live_service(target_url=target_url, timeout_seconds=timeout_seconds)

    @mcp.tool()
    def check_attack_surface(target_url: str, timeout_seconds: int = 10) -> str:
        """
        배포된 서비스의 대표 경로를 탐색해 공격자가 바로 시도할 표면을 점검한다.

        Parameters
        ----------
        target_url : str
            점검할 서비스 URL
        timeout_seconds : int
            요청 타임아웃
        """
        return analyze_attack_surface(target_url=target_url, timeout_seconds=timeout_seconds)

    @mcp.tool()
    def check_authenticated_flows(
        target_url: str,
        bearer_token: str = "",
        session_cookie: str = "",
        extra_headers: str = "",
        reference_user_id: str = "1",
        alternate_user_id: str = "2",
        timeout_seconds: int = 10,
    ) -> str:
        """
        일반 사용자 인증 정보를 사용해 관리자 접근과 IDOR 가능성을 점검한다.

        Parameters
        ----------
        target_url : str
            점검할 서비스 URL
        bearer_token : str
            일반 사용자용 Bearer 토큰
        session_cookie : str
            일반 사용자용 Cookie 헤더 값
        extra_headers : str
            추가 헤더. 줄바꿈 기준으로 `Header: value` 형식
        reference_user_id : str
            점검 기준이 되는 본인 사용자 ID
        alternate_user_id : str
            접근되면 안 되는 다른 사용자 ID
        timeout_seconds : int
            요청 타임아웃
        """
        return analyze_authenticated_flows(
            target_url=target_url,
            bearer_token=bearer_token or None,
            session_cookie=session_cookie or None,
            extra_headers=extra_headers or None,
            reference_user_id=reference_user_id,
            alternate_user_id=alternate_user_id,
            timeout_seconds=timeout_seconds,
        )

    @mcp.tool()
    def export_report(
        report_content: str,
        output_path: str,
        overwrite: bool = False,
        allowed_base_path: str = "",
    ) -> str:
        """
        점검 도구가 반환한 Markdown 리포트 문자열을 파일로 저장한다.

        Parameters
        ----------
        report_content : str
            저장할 보안 점검 리포트 내용
        output_path : str
            저장할 Markdown 파일 경로
        overwrite : bool
            False면 기존 파일이 있을 때 덮어쓰지 않는다.
        allowed_base_path : str
            값이 있으면 이 디렉터리 내부에만 리포트를 저장한다.
        """
        return export_report_to_file(
            report_content=report_content,
            output_path=output_path,
            overwrite=overwrite,
            allowed_base_path=allowed_base_path,
        )
