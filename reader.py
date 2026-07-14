from pathlib import Path
import csv
from typing import Generator

the_path = Path("network_traffic.log")


def get_lists(path: Path) -> Generator[list[str]]:
    with open(path, "r") as csvfile:
        lists_logs_generator = csv.reader(csvfile)
        for lst in lists_logs_generator:
            yield lst
