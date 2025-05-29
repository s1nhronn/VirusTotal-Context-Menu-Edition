import winreg
from contextlib import suppress
import sys
import os
import ctypes


def add_to_registry(api_key: str):
    key = winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, r'*\shell\VirusTotal')

    winreg.SetValueEx(key, 'MUIVerb', None, winreg.REG_SZ, "Check for viruses")
    winreg.SetValueEx(key, 'Icon', None, winreg.REG_SZ, os.getcwd() + r'\VirusTotal.ico')
    winreg.SetValueEx(key, 'APIKEY', None, winreg.REG_SZ, api_key)

    path_to_script = os.path.abspath('main.exe')

    winreg.SetValue(key, 'command', winreg.REG_SZ, path_to_script + ' "%1"')

    key.Close()


def remove_from_registry():
    winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, r'*\shell\VirusTotal\command')
    winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, r'*\shell\VirusTotal')


if __name__ == '__main__':
    if not ctypes.windll.shell32.IsUserAnAdmin():
        params = " ".join([f'"{arg}"' for arg in sys.argv])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        sys.exit()
    res = input('1 - Add the command to the context menu\n2 - Delete the command from the context menu\n[1/2]:')
    if res == '1':
        api_key = input('Enter your API-key: ')
        add_to_registry(api_key)
        print('Done')
        input('Press Enter to exit...')
    else:
        with suppress(FileNotFoundError):
            remove_from_registry()
        print('Done')
        input('Press Enter to exit...')
