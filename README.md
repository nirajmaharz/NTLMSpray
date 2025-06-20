# NTLMSpray

**NTLMSpray** is a command-line tool written in Python for performing NTLM password spraying attacks against web services that use NTLM authentication. 

---

## Features

- Supports single password or password list
- Detects NTLM authentication support before spraying
- Verbose mode for failed attempts
- Saves valid credentials to a file (optional)
- Color-coded output using `colorama`

---

## Requirements

- Python 3.x
- `requests`
- `requests_ntlm`
- `colorama`

Install dependencies with:

```bash
pip install -r requirements.txt
```

## Usage
python3 ntlmspray.py -u users.txt -f ZA.CORP.LOCAL -t http://target.local -p Welcome123

## Options to consider

| Option             | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| `-u USERFILE`      | Path to the file containing usernames (one per line).                       |
| `-f FQDN`          | Fully Qualified Domain Name (e.g., `corp.example.com`).                     |
| `-t TARGET`        | Target URL protected by NTLM authentication (e.g., `http://host.local`).    |
| `-p PASSWORD`      | Single password to spray.                                                   |
| `-P PASSWORDFILE`  | File containing list of passwords to spray (one per line).                  |
| `-o OUTFILE`       | File to save valid credential pairs. Optional.                              |
| `-v`               | Enable verbose output. Optional.                                            |

---

## Example Usage

### Spray using a single password:
```bash
python3 ntlm_spray.py -u usernames.txt -f ZA.CORP.LOCAL -t http://target.local -p Welcome123
```

### Spray using a password list and save valid credentials:
```bash
python3 ntlm_spray.py -u usernames.txt -f ZA.CORP.LOCAL -t http://target.local -P passwords.txt -o valid.txt -v
```
