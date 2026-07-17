from reader import *

from pathlib import Path
from reader import get_lists


def main():
    the_path = Path("network_traffic.log")
    logs_generator = get_lists(the_path)


if __name__ == "__main__":
    main()