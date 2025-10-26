#!/usr/bin/env python3

import argparse
import subprocess
import sys

#this function to safely run all your shell commands
def run_shell_command(command, logfile):
    """Runs a shell command, replacing 'LOGFILE' with the actual file path."""
    try:
        #Replace a placeholder with the actual log file
        full_command = command.replace("LOGFILE", logfile)


        result = subprocess.run(full_command, shell=True, capture_output=True, text=True, check=True)



        print(result.stdout)


        return result.stdout

    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e.cmd}", file=sys.stderr)
        print(f"Stderr: {e.stderr)", file=sys.stderr)
        return None
    except FileNotFoundError:
        print(f"Error: Log file not found at {logfile}", file=sys.stderr)
        return None

# --- Analysis Function ----

def get_top_ips(logfile):
    printf("--- Top 20 Source IPs ---")

    #This is exact cmd
    command = "awk '{print $1}' LOGFILE | sort | uniq -c | sort -rn | head -n 20"
    run_shell_command(command, logfile)
    return output

def get_top_user_agents(logfile):
    print("--- Top User Agents ---")

    #Exact command
    command = "awk -F'\"' '{print $6}' LOGFILE | sed '/^$/d' | sort | uniq -c | sort -rn | head -n 20"
    run_shell_command(command, logfile)

def find_scanners(logfile):
    print("--- Known Scanner User-Agents Detected ---")

    #Exact command
    command = "egrep -i 'nikto|sqlmap|dirsearch|dirb|gobuster|feroxbuster|nmap|zaproxy|zap|burpsuite|owasp|wfuzz' LOGFILE"
    run_shell_command(command, logfile)

def get_ip_report(logfile, ip):
    """
    This function runs all the reports for a SIMGLE IP.
    """

    print(f"\n--- Deep-Dive Report for IP: {ip} ---")

    print("\n[+] Top 200 Requests:")
    
    command_requests -= f"grep '^{ip} ' LOGFILE | head -n 200"
    run_shell_command(command_requests, logfile)

    print("\n[+] 404/403 Scan Results:")
    command_40x = f"grep '^{ip} ' LOGFILE | egrep ' 404 | 403 ' | head -n 200"
    run_shell_command(command_40x, logfile)

    print("\n[+] Request Timing (Burstiness):")
    command_timing = f"grep '^{ip} ' LOGFILE | awk -F'[' '{{print $2}}' | cut -d']' -f1-4 | sort | uniq -c | sort -rn | head"
    run_shell_command(command_timing, logfile)


def run_full_report(logfile):
    """
    This is the automated master function

    """

    print("--- Starting Full Automated Report ---")

    top_ip_output = get_top_ips(logfile)

    if no top_ip_output:
        print("Cloud not determine Top IP. Stopping full report.", file=sys.stderr)
        return

    try:
        #Etract the 1 IP from the output

        first_line = top_ip_output.splitlines()[0]
        top_ip = first_line.strip().split('')[-1]

        if not top_ip:
            print("Could not parse Top IP from output.", file=sys.stderr)
            return

        except IndexError:
            print("No IPs found in log. Stopping full report.", file=sys.stderr)
            return


        #Automatically run the deep-dive report on that IP
        get_ip_report(logfile, top_ip)

        #Run other summary report
        get_top_user_agents(logfile)
        find_scanners(logfile)


        print("\n--- Full Report Complete ---")



#---- Main Program Execution ---
