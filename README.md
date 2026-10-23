# Automated Web Security Header Scanner

## Project overview
A beginner-friendly Python command-line tool that sends a normal HTTP GET request to an authorized website and checks for common security response headers. It also reports the `Access-Control-Allow-Origin` CORS header for review.

## Features
- Checks six common security headers.
- Shows HTTP status and final URL after redirects.
- Notes whether the CORS allow-origin header is present.
- Prints a simple summary.
- Uses a timeout and handles request errors.

## Requirements
- Python 3.10 or later
- VS Code (recommended)
- Internet connection
- Permission to test the target website

## Run in VS Code
1. Extract the ZIP file.
2. Open the extracted folder in VS Code.
3. Open the terminal (`Terminal > New Terminal`).
4. Create a virtual environment (recommended):
   - Windows: `python -m venv .venv`
   - Activate: `.venv\Scripts\activate`
   - macOS/Linux: `python3 -m venv .venv`
   - Activate: `source .venv/bin/activate`
5. Install dependency: `python -m pip install -r requirements.txt`
6. Run: `python main.py`
7. Enter a domain you own or are authorized to assess, or run `python main.py https://example.com`.

## Important limitations
This is an educational header checker, not a complete penetration-testing tool. A missing header does not automatically mean a site is vulnerable. The tool does not test authentication, application logic, or exploit vulnerabilities. Only test systems with permission.
