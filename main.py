import argparse
import sys
from parser import parse_log_file
from analyzer import analyze_traffic, detect_brute_force

def main():
    parser = argparse.ArgumentParser(description="LogSentinel: Server Log Analyzer & Threat Detector")
    parser.add_argument("--log-file", type=str, required=True, help="Path to the server access log file.")
    parser.add_argument("--top-ips", type=int, default=5, help="Number of top IPs to display.")
    parser.add_argument("--detect-threats", action="store_true", help="Enable brute-force threat detection.")
    parser.add_argument("--export-csv", type=str, help="Path to export the summary as CSV.")
    
    args = parser.parse_args()
    
    print(f"[*] Analyzing log file: {args.log_file}")

    # 1. Parse the log file
    logs = parse_log_file(args.log_file)
    if not logs:
        print("[-] No valid logs found or file read error.")
        sys.exit(1)

    # 2. Analyze traffic
    analyze_traffic(logs, top_n=args.top_ips, export_path=args.export_csv)

    # 3. Detect threats if requested
    if args.detect_threats:
        detect_brute_force(logs)

    print("[+] Analysis complete.")

if __name__ == "__main__":
    main()
