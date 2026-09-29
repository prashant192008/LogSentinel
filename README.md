# LogSentinel: Advanced Server Log Analyzer & Threat Detector

LogSentinel is a robust and visually engaging command-line utility built in Python. It parses standard web server logs (such as Apache or Nginx), performs comprehensive traffic analysis, and detects potential malicious activities, like brute-force attacks on sensitive endpoints.

## 🌟 Features

- **Standard Log Parsing:** Employs precise regular expressions to extract key components from Apache/Nginx combined log formats (IP, Datetime, Method, Request, Status, Size).
- **Traffic Analysis:** Instantly summarizes essential metrics including:
  - Total requests processed.
  - Total 404 (Not Found) errors.
  - Count of unique IP addresses accessing your server.
  - Top N most active IP addresses.
- **Threat Detection:** Specifically designed to monitor and detect brute-force attack attempts (e.g., repeatedly targeting `/login` endpoints exceeding a secure threshold).
- **Beautiful CLI Output:** Utilizes the `rich` library to present tables, panels, and styled texts for an intuitive and eye-catching user experience directly in your terminal.
- **Data Export:** Seamlessly export the traffic analysis data (top IPs and request counts) to a CSV format for reporting or further investigation.

## 🚀 Environment Setup

LogSentinel requires **Python 3.8+**.

1. **Clone the repository and navigate to the folder:**
   ```bash
   git clone https://github.com/prashant192008/LogSentinel.git
   cd LogSentinel
   ```

2. **Create a virtual environment (Recommended):**
   ```bash
   python -m venv venv
   
   # On macOS / Linux:
   source venv/bin/activate
   
   # On Windows:
   venv\Scripts\activate
   ```

3. **Install the dependencies:**
   The only major external dependency is `rich` for terminal UI formatting.
   ```bash
   pip install -r requirements.txt
   ```

## 🛠️ Usage Guide

LogSentinel comes with an intuitive CLI. You can view all available arguments via the help command:
```bash
python main.py --help
```

### 1. Basic Traffic Analysis
Analyze a log file to extract total metrics and display the top 5 most active IP addresses:
```bash
python main.py --log-file samples/sample_access.log --top-ips 5
```

### 2. Exporting Results
Generate a comprehensive traffic report in CSV format:
```bash
python main.py --log-file samples/sample_access.log --export-csv report.csv
```
This will produce a `report.csv` file containing the rank, IP address, and request count.

### 3. Threat Detection (Brute-Force)
Enable heuristics to detect repeated access to sensitive endpoints (e.g., login attempts):
```bash
python main.py --log-file samples/sample_access.log --detect-threats
```
If a specific IP exceeds the secure threshold of requests to an endpoint, LogSentinel triggers a visual threat alert panel in the console.

### 4. Combined Execution
You can combine multiple flags to perform traffic analysis, detect threats, and export findings all in a single run:
```bash
python main.py --log-file samples/sample_access.log --top-ips 10 --detect-threats --export-csv full_report.csv
```

## 📁 Project Structure

- `main.py` - The entry point of the application handling CLI arguments.
- `parser.py` - Contains the logic and regex configurations for parsing combined access logs.
- `analyzer.py` - Performs the statistical analysis and threat detection heuristics, heavily featuring `rich` UI elements.
- `requirements.txt` - Lists project dependencies.
- `samples/` - Contains sample access logs (`sample_access.log`) for testing.

## 🛡️ License
This project is open-source. Feel free to modify and distribute.
