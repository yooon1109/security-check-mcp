def format_result(data: dict) -> str:
    """딕셔너리를 읽기 쉬운 문자열로 변환합니다."""
    return "\n".join(f"{k}: {v}" for k, v in data.items())
