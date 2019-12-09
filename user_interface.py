import os, sys, getopt, shutil

try:
    opts, args = getopt.getopt(sys.argv[1:], shortopts='h',
                               longopts=['help', 'MKD=', 'mkd=', 'RMD=', 'rmd=',
                                         'GWD', 'gwd', 'CWD=', 'cwd=',
                                         'LST', 'lst', 'UPL=', 'upl=',
                                         'DNL=', 'dnl=', 'RMF=', 'rmf='])
except getopt.GetoptError:
    print('Error: Unknown option detected.')
    print('Type "userinterface.py -h" for help.')
    sys.exit(1)

folder_name = ''
file_name = ''

def change_dir(f):
    try:
        os.chdir(os.path.join(os.getcwd(), f))
        print("Changed to directory {0}.".format(os.path.basename(os.getcwd())))
    except Exception as e:
        print(e)

def make_dir(f):
    try:
        os.mkdir(os.path.join(os.getcwd(), f))
        print("Directory {0} created on server.".format(f))
    except Exception as e:
        print(e)

def remove_dir(f):
    dir_name = os.path.join(os.getcwd(), f)
    try:
        os.rmdir(dir_name)
        print("Directory {0} successfully removed.".format(f))
    except Exception as e:
        print(e)

def upload_f(f):
    try:
        # path to file
        src = 'path/to/file'
        dst = 'path/to/user_folder_on_server'
        shutil.copy2(src, dst)
    except Exception as e:
        print(e)

def download_f(f):
    try:
        # path to folder that server stores the file
        cur_dir = os.getcwd()
        src = os.path.join(cur_dir, f)
        dst = 'path/to/dest_dir'
        shutil.copy2(src, dst)
    except Exception as e:
        print(e)

def remove_f(f):
    try:
        file = os.path.join(os.getcwd(), f)
        os.remove(file)
    except Exception as e:
        print(e)

def print_dir_name():
    print("Current working directory: {0}".format(os.path.basename(os.getcwd())))

def  print_dir_content():
    with os.scandir(os.getcwd()) as entries:
        for entry in entries:
            if entry.name[0] not in ('.', '_'):
                print(entry.name)


for opt, arg in opts:
    if opt == '-h' or opt == '--help':
        print('Usage: python3 script.py -command <path>')
        print('Available commands:')
        print('[--CWD <folder name>] \t Change working directory to this folder')
        print('[--MKD <folder name>] \t Create a folder on the server')
        print('[--RMD <folder name>] \t Remove a folder from the server')
        print('[--UPL <file path>] \t Upload a file to the server')
        print('[--DNL <file name>] \t Download a file from the server')
        print('[--RMF <file name>]  \t Remove a file from a folder on the server')
        print('[--GWD <none>] \t \t Print the name of the current working directory')
        print('[--LST <none>] \t \t List the content of a folder')
        sys.exit(0)
    elif opt in ('--CWD', '--cwd'):
        folder_name = arg
        change_dir(folder_name)
    elif opt in ('--MKD', '--mkd'):
        folder_name = arg
        make_dir(folder_name)
    elif opt in ('--RMD', '--rmd'):
        folder_name = arg
        remove_dir(folder_name)
    elif opt in ('--UPL', '--upl'):
        file_name = arg
        upload_f(file_name)
    elif opt in ('--DNL', '--dnl'):
        file_name = arg
        download_f(file_name)
    elif opt in ('--RMF', '--rmf'):
        file_name = arg
        remove_f(file_name)
    elif opt in ('--GWD', '--gwd'):
        print_dir_name()
    elif opt in ('--LST', '--lst'):
        print_dir_content()