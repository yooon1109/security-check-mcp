from pathlib import Path
from threading import Thread
from http.server import BaseHTTPRequestHandler, HTTPServer

from src.tools.security_tools import (
    analyze_attack_surface,
    analyze_authenticated_flows,
    analyze_live_service,
    analyze_project,
)


def test_analyze_project_reports_release_blocker_without_fix_guidance(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        """
        {
          "dependencies": {
            "express": "^4.0.0",
            "react": "^18.0.0"
          }
        }
        """.strip(),
        encoding="utf-8",
    )
    (tmp_path / "app.js").write_text(
        """
        const express = require("express");
        const app = express();
        const api_key = "sk_test_1234567890";
        app.get("/admin", (req, res) => res.send("ok"));
        """.strip(),
        encoding="utf-8",
    )

    report = analyze_project(str(tmp_path))

    assert "출시 판정: 출시 차단" in report
    assert "왜 위험한가" in report
    assert "주요 이슈 요약" in report
    assert "바로 수정할 일" not in report
    assert "개발자에게 전달할 요청" not in report
    assert "수정 완료 확인 방법" not in report
    assert "express" in report
    assert "하드코딩된 API 키" in report


def test_analyze_project_reports_clean_project_without_blocker(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        """
        [project]
        name = "demo"
        dependencies = ["fastapi"]
        """.strip(),
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        """
        from fastapi import FastAPI

        app = FastAPI()

        @app.get("/health")
        def health():
            return {"ok": True}
        """.strip(),
        encoding="utf-8",
    )

    report = analyze_project(str(tmp_path))

    assert "출시 판정: 기본 점검 통과" in report
    assert "fastapi" in report
    assert "커버리지와 한계" in report


def test_analyze_project_detects_framework_specific_findings(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("django\n", encoding="utf-8")
    (tmp_path / "manage.py").write_text("print('django')\n", encoding="utf-8")
    (tmp_path / "settings.py").write_text(
        """
        DEBUG = True
        ALLOWED_HOSTS = ["*"]
        """.strip(),
        encoding="utf-8",
    )

    report = analyze_project(str(tmp_path))

    assert "django" in report
    assert "Django DEBUG 활성화" in report
    assert "Django ALLOWED_HOSTS 전체 허용 가능성" in report
    assert "출시 판정: 출시 차단" in report


def test_analyze_project_detects_nestjs_specific_finding(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        """
        {
          "dependencies": {
            "@nestjs/core": "^10.0.0",
            "nestjs": "^10.0.0"
          }
        }
        """.strip(),
        encoding="utf-8",
    )
    (tmp_path / "main.ts").write_text(
        """
        import { NestFactory } from '@nestjs/core';
        import { AppModule } from './app.module';

        async function bootstrap() {
          const app = await NestFactory.create(AppModule);
          await app.listen(3000);
        }
        bootstrap();
        """.strip(),
        encoding="utf-8",
    )

    report = analyze_project(str(tmp_path))

    assert "nestjs" in report
    assert "NestJS ValidationPipe 부재 가능성" in report
    assert "출시 판정: 기본 점검 통과" in report or "출시 판정: 수정 후 재점검" in report


class _LiveSecurityHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Server", "DemoServer/1.2")
        self.send_header("Set-Cookie", "sessionid=abc123; Path=/")
        self.end_headers()
        self.wfile.write(b"Traceback: demo error")

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


class _AttackSurfaceHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/admin":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"admin panel")
            return
        if self.path == "/users/1":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"id":1,"email":"demo@example.com"}')
            return
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        self.send_response(404)
        self.end_headers()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Allow", "GET, POST, PUT, DELETE, OPTIONS")
        self.end_headers()

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


class _AuthenticatedFlowHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        auth = self.headers.get("Authorization", "")
        if auth != "Bearer user-token":
            self.send_response(401)
            self.end_headers()
            return
        if self.path == "/admin":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"admin dashboard")
            return
        if self.path == "/users/1":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"id":1,"email":"me@example.com"}')
            return
        if self.path == "/users/2":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"id":2,"email":"other@example.com"}')
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def test_analyze_live_service_reports_header_and_cookie_issues() -> None:
    server = HTTPServer(("127.0.0.1", 0), _LiveSecurityHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"

    try:
        report = analyze_live_service(url, timeout_seconds=2)
    finally:
        server.shutdown()
        thread.join()

    assert "라이브 서비스 CORS 전체 허용" in report
    assert "라이브 서비스 세션 쿠키 보호 속성 누락" in report
    assert "라이브 서비스 에러 페이지 노출" in report
    assert "개발팀 전달용 요약" not in report
    assert "출시 판정: 출시 차단" in report


def test_analyze_attack_surface_reports_public_admin_and_idor_signals() -> None:
    server = HTTPServer(("127.0.0.1", 0), _AttackSurfaceHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"

    try:
        report = analyze_attack_surface(url, timeout_seconds=2)
    finally:
        server.shutdown()
        thread.join()

    assert "관리자 경로 무인증 노출 가능성" in report
    assert "순차 ID 기반 데이터 노출 가능성" in report
    assert "위험한 HTTP 메서드 노출 가능성" in report
    assert "수정 후 확인 순서" not in report
    assert "출시 판정: 출시 차단" in report


def test_analyze_attack_surface_returns_error_when_unreachable() -> None:
    report = analyze_attack_surface("http://127.0.0.1:9", timeout_seconds=1)

    assert report.startswith("오류: 공격 표면 점검을 수행하지 못했습니다")


def test_analyze_authenticated_flows_reports_admin_access_and_idor() -> None:
    server = HTTPServer(("127.0.0.1", 0), _AuthenticatedFlowHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"

    try:
        report = analyze_authenticated_flows(
            url,
            bearer_token="user-token",
            reference_user_id="1",
            alternate_user_id="2",
            timeout_seconds=2,
        )
    finally:
        server.shutdown()
        thread.join()

    assert "일반 사용자로 관리자 경로 접근 가능성" in report
    assert "인증 상태 IDOR 가능성" in report
    assert "담당자 추천" not in report
    assert "출시 판정: 출시 차단" in report


def test_analyze_authenticated_flows_requires_auth_context() -> None:
    report = analyze_authenticated_flows("https://example.com")

    assert report.startswith("오류: 인증 기반 점검에는")
