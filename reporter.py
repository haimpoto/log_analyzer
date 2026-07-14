from typing import Generator
from checks import *
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


def analyze_ip_activity(logs: Generator[list[str]]) -> dict[str, list[str]]:
    dictionary = {}
    for log in logs:
        lst = []
        if is_external_IP(log):
            lst.append("EXTERNAL_IP")
        if is_sensitive_port(log):
            lst.append("SENSITIVE_PORT")
        if is_large_packet(log):
            lst.append("LARGE_PACKET")
        if is_night_activity(log):
            lst.append("NIGHT_ACTIVITY")
        if not lst:
            continue
        if log[1] not in dictionary:
            dictionary[log[1]] = []
        for tag in lst:
            if tag not in dictionary[log[1]]:
                dictionary[log[1]].append(tag)
    return dictionary


print(analyze_ip_activity(reader.get_lists(reader.the_path)))
results = analyze_ip_activity(reader.get_lists(reader.the_path))

# כתיבה לקובץ במקום הדפסה לטרמינל
with open("output.txt", "w") as f:
    for ip, tags in results.items():
        f.write(f"{ip}: {tags}\n")

print("Finished! Check output.txt for the full results.")