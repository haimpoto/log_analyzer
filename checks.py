from typing import Generator


def extract_external_IP(logs: Generator[list[str]]) -> Generator[str]:
    external_IP_list = (lst[1] for lst in logs if not (lst[1].startswith("10.") or lst[1].startswith("192.168")))
    return external_IP_list


def extract_external_port(logs: Generator[list[str]]) -> Generator[list[str]]:
    external_port_list = (lst for lst in logs if (lst[3] == "22" or lst[3] == "23" or lst[3] == "3389"))
    return external_port_list


def extract_large_port(logs: Generator[list[str]]) -> Generator[list[str]]:
    external_large_list = (lst for lst in logs if int(lst[5]) >= 5000)
    return external_large_list
