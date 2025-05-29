import time
import winreg
import sys
from contextlib import suppress
import vt
import colorama
import threading
import hashlib


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


stop = False


def load_animation():
    while not stop:
        if stop:
            break
        print('\rScan the resulting file.  ', end='', flush=True)
        time.sleep(0.5)
        if stop:
            break
        print('\rScan the resulting file.. ', end='', flush=True)
        time.sleep(0.5)
        if stop:
            break
        print('\rScan the resulting file...', end='', flush=True)
        if stop:
            break
        time.sleep(0.5)


if __name__ == '__main__':
    try:
        colorama.init()
        path = sys.argv[1]
        print(bcolors.HEADER + 'File: ' + path + bcolors.ENDC)
        hash_ = hashlib.md5(open(path, 'rb').read()).hexdigest()
        try:
            key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, '*\\shell\\VirusTotal')
        except FileNotFoundError:
            import platform

            bitness = platform.architecture()[0]
            other_view_flag = None
            if bitness == '32bit':
                other_view_flag = winreg.KEY_WOW64_64KEY
            elif bitness == '64bit':
                other_view_flag = winreg.KEY_WOW64_32KEY

            key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, '*\\shell\\VirusTotal',
                                 access=winreg.KEY_READ | other_view_flag)
        api_key = winreg.QueryValueEx(key, 'APIKEY')[0]
        key.Close()

        # Сканирование файла и вывод ответа
        print(bcolors.BOLD, end='')
        p = threading.Thread(target=load_animation)
        p.start()
        client = vt.Client(api_key)
        with suppress(vt.error.APIError):
            file_info = client.get_object('/files/' + hash_)
            antivirus_results = file_info.to_dict()['attributes']['last_analysis_results']
            stop = True
            print(bcolors.BOLD + '\rCheck the results...     ' + bcolors.ENDC)
            dct = {}
            for i in antivirus_results:
                if antivirus_results[i]['result'] is not None:
                    dct[i] = antivirus_results[i]
            if dct:
                print(bcolors.FAIL + 'Viruses are found in the file!\n' + bcolors.ENDC)
                print(bcolors.UNDERLINE + 'Antivirus: Type of threat' + bcolors.ENDC)
                for i in dct:
                    print(bcolors.OKGREEN + i + bcolors.ENDC + ': ' + bcolors.FAIL + dct[i]['result'] + bcolors.ENDC)
            else:
                print(bcolors.OKGREEN + 'There are no viruses in the file!' + bcolors.ENDC)
            print(f'See on the site: https://www.virustotal.com/gui/file/{hash_}')

            client.close()
            print()
            input('Press Enter to exit...')
            sys.exit()
        with open(path, 'rb') as file:
            res = client.scan_file(file, wait_for_completion=True).to_dict()
        antivirus_results = res['attributes']['results']
        stop = True
        print(bcolors.BOLD + '\rCheck the results...     ' + bcolors.ENDC)
        dct = {}
        for i in antivirus_results:
            if antivirus_results[i]['result'] is not None:
                dct[i] = antivirus_results[i]
        if dct:
            print(bcolors.FAIL + 'In the file, viruses or trousers are found!\n' + bcolors.ENDC)
            print(bcolors.UNDERLINE + 'Antivirus: Type of threat' + bcolors.ENDC)
            for i in dct:
                print(bcolors.OKGREEN + i + bcolors.ENDC + ': ' + bcolors.FAIL + dct[i]['result'] + bcolors.ENDC)
        else:
            print(bcolors.OKGREEN + 'There are no viruses in the file!' + bcolors.ENDC)
        print(f'See on the site: https://www.virustotal.com/gui/file/{hash_}')

        client.close()
    except Exception as e:
        print(bcolors.FAIL + f'An error occurred: {e}' + bcolors.ENDC)
    print()
    input('Press Enter to exit...')
