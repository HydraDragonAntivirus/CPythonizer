# Self-contained Cython --embed demo (no third-party imports).
# Transpiled to C by Cython, compiled by Visual Studio 2022.


def fib(n: int) -> int:
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a


def main() -> int:
    print("Hello from Cython + Visual Studio!")
    print(f"fib(30) = {fib(30)}")
    total = 0
    for i in range(1000000):
        total += i
    print(f"sum(0..999999) = {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
