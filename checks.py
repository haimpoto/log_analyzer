from typing import Generator
import reader


def extract_external_IP(logs: Generator[list[str]]) -> list[str]:
    external_IP_list = [lst[2] for lst in logs if not (lst[2].startswith("10") or lst[2].startswith("192.168")
    return external_IP_list