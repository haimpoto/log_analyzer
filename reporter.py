from typing import Generator
import reader


def get_source_ip(logs: Generator[list[str]]) -> dict[str, int]:
    dictionary = {}
    for log in logs:
        if log[1] not in dictionary:
            dictionary[log[1]] = 0
        dictionary[log[1]] += 1
    return dictionary


def map_port_to_protocol(logs: Generator[list[str]]) -> dict[str, str]:
    return {log[3]: log[4] for log in logs}


print(map_port_to_protocol(reader.get_lists(reader.the_path)))
