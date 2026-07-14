from config import *


def is_external_IP(lst: list[str]) -> bool:
    return lst[1].startswith(EXTERNAL_IP)


def is_external_port(lst: list[str]) -> bool:
    return lst[3] in EXTERNAL_PORT


def is_large_port(lst: list[str]) -> bool:
    return int(lst[5]) >= MAX_NORMAL_SIZE
