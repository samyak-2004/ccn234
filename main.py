# main.py
import sys
from nlp_module.parser import parse_command
from execution_module.executor import execute_command
from logger.custom_logger import log_event

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class DummyColor:
        def __getattr__(self, name):
            return ''
    Fore = Style = DummyColor()

def main():
    print(Fore.CYAN + "Network Security Management System - Text Command Interface")
    print("Type a command (e.g., 'Block port 22', 'Block IP 192.168.1.100', 'Show blocked', 'Unblock IP 192.168.1.100')")
    print("Type 'exit', 'quit', or press CTRL+C to quit.")

    try:
        while True:
            user_input = input(Fore.YELLOW + "\nEnter command: ").strip()

            # Skip empty commands
            if not user_input:
                continue

            # Exit conditions
            if user_input.lower() in ["exit", "quit", "exit()", "quit()"]:
                print(Fore.RED + "Exiting system...")
                log_event("system", "Exited the system.")
                break

            # Parse the command using the NLP module
            parsed_cmd = parse_command(user_input)
            print(Fore.BLUE + f"Parsed Command: {parsed_cmd}")

            # Execute the parsed command and get the result
            result = execute_command(parsed_cmd)
            print(Fore.GREEN + f"Execution Result: {result}")

            # Log the executed command
            log_event("system", f"Executed command: {user_input}")

    except KeyboardInterrupt:
        print(Fore.RED + "\nCTRL+C detected. Exiting system...")
        log_event("system", "Exited the system via CTRL+C")
        sys.exit(0)

if __name__ == "__main__":
    main()
