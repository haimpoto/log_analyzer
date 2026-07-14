from typing import Generator


def get_source_IP_dictionary(logs: Generator[list[str]]) -> dict[str, int]:
    dictionary = {}
    for log in logs:
        if log[1] not in dictionary:
            dictionary[log[1]] = 0
        dictionary[log[1]] += 1
    return dictionary
