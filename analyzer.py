from typing import Generator
from checks import *


def extract_external_IP(logs: Generator[list[str]]) -> Generator[str]:
    external_IP_list = (log[1] for log in logs if not is_external_IP(log))
    return external_IP_list


def filter_by_external_port(logs: Generator[list[str]]) -> Generator[list[str]]:
    external_port_list = (log for log in logs if is_external_port(log))
    return external_port_list


def filter_by_large_port(logs: Generator[list[str]]) -> Generator[list[str]]:
    external_large_list = (log for log in logs if is_large_port(log))
    return external_large_list


def append_tag(logs: Generator[list[str]]) -> Generator[list[str]]:
    for log in logs:
        if is_large_port(log):
            yield log + ["LARGE"]
        else:
            yield log + ["NORMAL"]
