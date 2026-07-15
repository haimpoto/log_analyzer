from config import *


def is_external_IP(log: list[str]) -> bool:
    return not log[1].startswith(INTERNAL_IP)


def is_sensitive_port(log: list[str]) -> bool:
    return log[3].strip() in EXTERNAL_PORTS


def is_large_packet(log: list[str]) -> bool:
    return int(log[5]) >= MAX_NORMAL_SIZE


def is_night_activity(log: list[str]) -> bool:
    return int(EXIT_TIME[:2]) <= int(log[0][11:13]) < int(ENTER_TIME[:2])


