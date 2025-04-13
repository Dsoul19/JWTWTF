import sys
from interface.cli import CLI
from interface.gui import JWTWTFGUI

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--gui":
        app = JWTWTFGUI()
        app.run()
    else:
        shell = CLI()
        shell.run()

if __name__ == "__main__":
    main()