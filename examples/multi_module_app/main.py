import sys
import utils
import core
from core.math_ops import multiply, add

def main():
    print("----------------------------------------")
    print(core.APP_TITLE)
    print(utils.format_message("CPythonizer User"))
    print(f"multiply(6, 7) = {multiply(6, 7)}")
    print(f"add(100, 250)  = {add(100, 250)}")
    print("----------------------------------------")
    print("SUCCESS: Local modules imported and executed perfectly!")

if __name__ == "__main__":
    main()
