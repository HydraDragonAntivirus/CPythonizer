# Single-file example: no imports, no dependencies.
# Build: python -m cpythonizer vs-build examples/single_hello.py --name Hello


def factorial(n: int) -> int:
    result = 1
    for i in range(2, n + 1):
        result *= i
    return result


def main() -> int:
    print("Single-file Cython + VS2022 build works!")
    print(f"factorial(20) = {factorial(20)}")
    # Wait in a loop so the window stays open until the user quits.
    while True:
        cmd = input("number (q=quit): ").strip().lower()
        if cmd in ("q", "quit", "exit"):
            break
        try:
            print(f"factorial = {factorial(int(cmd))}")
        except ValueError:
            print("enter a number, or q to quit")
    print("bye!")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
