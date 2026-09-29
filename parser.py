import re

# Standard Apache/Nginx combined log format regex
LOG_REGEX = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] "(?P<method>[A-Z]+) (?P<request>[^\s]+) [^"]+" (?P<status>\d{3}) (?P<size>\d+|-)'
)

def parse_log_file(filepath):
    """
    Reads a log file line by line and extracts relevant fields using LOG_REGEX.
    Returns a list of dictionaries representing the parsed log entries.
    """
    parsed_logs = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                match = LOG_REGEX.match(line.strip())
                if match:
                    parsed_logs.append(match.groupdict())
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: '{filepath}'")
    return parsed_logs
