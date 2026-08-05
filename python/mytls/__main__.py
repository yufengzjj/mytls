"""`python -m mytls` - is this installation actually able to do what it claims?"""

from . import catalog, check

if __name__ == "__main__":
    print(check())
    print()
    print(catalog())
