from pathlib import Path
from checks import *
import reader


counter_logs_checks = 0
counter_suspicious_logs = 0
suspicion_counts = {
    "EXTERNAL_IP": 0,
    "SENSITIVE_PORT": 0,
    "LARGE_PACKET": 0,
    "NIGHT_ACTIVITY": 0
}


def update_stats(suspicion_list: list[str]):
    global counter_suspicious_logs, suspicion_counts
    if suspicion_list:
        counter_suspicious_logs += 1
        for suspicion in suspicion_list:
            if suspicion in suspicion_counts:
                suspicion_counts[suspicion] += 1


def the_analyze(filename: Path) -> dict[str, list[str]]:
    global counter_logs_checks
    dictionary = {}
    logs = reader.get_lists(filename)
    for log in logs:
        counter_logs_checks += 1
        suspicions = get_log_suspicions(log, get_suspicion_checks_dict())
        update_stats(suspicions)
        if suspicions:
            dictionary[log[1]] = suspicions
    return dictionary


def filter_external_IP(logs: Generator[list[str]]) -> Generator[str]:
    external_IP_list = (log[1] for log in logs if is_external_IP(log))
    return external_IP_list


def filter_sensitive_port(logs: Generator[list[str]]) -> Generator[list[str]]:
    external_port_list = (log for log in logs if is_sensitive_port(log))
    return external_port_list


def filter_large_packets(logs: Generator[list[str]]) -> Generator[list[str]]:
    external_large_list = (log for log in logs if is_large_packet(log))
    return external_large_list


def tag_traffic_size(logs: Generator[list[str]]) -> Generator[list[str]]:
    for log in logs:
        if is_large_packet(log):
            yield log + ["LARGE"]
        else:
            yield log + ["NORMAL"]

def count_requests_per_ip(logs: Generator[list[str]]) -> dict[str, int]:
    dictionary = {}
    for log in logs:
        if log[1] not in dictionary:
            dictionary[log[1]] = 0
        dictionary[log[1]] += 1
    return dictionary

def map_port_to_protocol(logs: Generator[list[str]]) -> dict[str, str]:
    return {log[3]: log[4] for log in logs}

def map_ips_to_suspicions(logs: Generator[list[str]]) -> dict[str, list[str]]:
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

def filter_multiple_suspicions(dictionary: dict[str, list[str]]) -> dict[str, list[str]]:
    return {key: val for key, val in dictionary.items() if len(val) >= 2}


def extract_hours_with_maps(logs: Generator[list[str]]) -> list[int]:
    return list(map(lambda log: int(log[0][11:13]), logs))


def convert_size_to_kb_with_map(logs: Generator[list[str]]) -> list[int]:
    return list(map(lambda log: int(log[5]) / 1024, logs))


def filter_sensitive_ports_with_lambda(logs: Generator[list[str]]) -> filter:
    return filter(lambda log: is_sensitive_port(log), logs)


def filter_night_activity_with_lambda(logs: Generator[list[str]]) -> filter:
    return filter(lambda log: is_night_activity(log), logs)


def get_suspicion_checks_dict() -> dict:
    return {
        "EXTERNAL_IP": lambda log: not log[1].startswith(INTERNAL_IP),
        "SENSITIVE_PORT": lambda log: log[3].strip() in EXTERNAL_PORTS,
        "LARGE_PACKET": lambda log: int(log[5]) >= MAX_NORMAL_SIZE,
        "NIGHT_ACTIVITY": lambda log: int(EXIT_TIME[:2]) <= int(log[0][11:13]) < int(ENTER_TIME[:2])
    }

def get_log_suspicions(log: list[str], checks_dict: dict) -> list[str]:
    return list(filter(lambda suspicion: checks_dict[suspicion](log), checks_dict))

def filter_suspicious_logs_with_map(logs: Generator[list[str]], checks_dict: dict) -> filter:
    return filter(lambda item: len(item[1]) > 0, map(lambda log: (log, get_log_suspicions(log, checks_dict)), logs))
