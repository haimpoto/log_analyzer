from typing import Generator
from checks import *
import reader


# stage_1 functions
def extract_external_IP(logs: Generator[list[str]]) -> Generator[str]:
    external_IP_list = (lst[1] for lst in logs if not is_external_IP(lst))
    return external_IP_list


def filter_by_external_port(logs: Generator[list[str]]) -> Generator[list[str]]:
    external_port_list = (lst for lst in logs if is_external_port(lst))
    return external_port_list


def filter_by_large_port(logs: Generator[list[str]]) -> Generator[list[str]]:
    external_large_list = (lst for lst in logs if is_large_port(lst))
    return external_large_list


def append_tag(logs: Generator[list[str]]) -> Generator[list[str]]:
    for lst in logs:
        if is_large_port(lst):
            yield lst + ["LARGE"]
        else:
            yield lst + ["NORMAL"]


# stage_2 functions
def get_source_IP_dictionary(logs: Generator[list[str]]) -> dict[str, int]:
    dictionary = {}
    for log in logs:
        if log[1] not in dictionary:
            dictionary[log[1]] = 0
        dictionary[log[1]] += 1
    return dictionary

print(get_source_IP_dictionary(reader.get_lists(reader.the_path)))

