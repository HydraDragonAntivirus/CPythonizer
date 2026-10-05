import requests


def main():
    print("Testing requests in CPythonizer standalone binary...")
    print(f"requests version: {requests.__version__}")
    r = requests.get("https://httpbin.org/get", timeout=10)
    print(f"Status code: {r.status_code}")
    print(f"Headers user-agent: {r.request.headers.get('User-Agent')}")
    print("Success!")
    return 0


if __name__ == "__main__":
    main()
