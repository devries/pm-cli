import subprocess
import platform
import getpass
import argparse
import os
import stat
import sys
import pmcli.dbutil as dbutil

def main():
    parser = argparse.ArgumentParser(description="Command Line password manager")
    parser.add_argument('--config', dest='config_file', default=os.path.expanduser('~/.pmcli.db'))
    parser.add_argument('location', help='location for password or notes')
    parser.add_argument('username', nargs='?', default=None, help='username')

    args = parser.parse_args()

    if os.path.exists(args.config_file):
        statinfo = os.stat(args.config_file)
        mode = stat.S_IMODE(statinfo.st_mode)

        if mode&stat.S_IROTH>0 or mode&stat.S_IRGRP>0:
            sys.stderr.write('Config file is either group or other readable.')
            return 1

    else:
        dbutil.create_database(args.config_file)
        os.chmod(args.config_file, stat.S_IRUSR|stat.S_IWUSR)

    conn = dbutil.open_database(args.config_file)

    pwloop = True

    if dbutil.is_master_password_set(conn): 
        while pwloop:
            pw = getpass.getpass('Master Password: ')
            key = dbutil.verify_master_password(conn, pw)
            if key is None:
                sys.stdout.write('ERROR: Incorrect password.\n')
            else:
                pwloop = False
    else:
        while pwloop:
            pw = getpass.getpass('Select Master Password: ')
            pw2 = getpass.getpass('Retype Master Password: ')

            if pw==pw2:
                key = dbutil.set_master_password(conn, pw)
                pwloop = False
            else:
                sys.stdout.write('Passwords do not match.\n')

    if args.username is None:
        usernames = [t[0] for t in dbutil.item_generator(conn, args.location)]
        if len(usernames)>1:
            sys.stdout.write('Please select a username below.\n')
            for i, username in enumerate(usernames,1):
                sys.stdout.write('%d. %s\n'%(i, username))

            selection = input('Selection: ').strip()
            args.username = usernames[int(selection)-1]

        elif len(usernames)==1:
            args.username=usernames[0]

        else:
            sys.stdout.write('No existing username found. Type in a username to set up a password.\n')
            args.username = input('Username: ').strip()

    password, notes = dbutil.retrieve_password_and_notes(conn, key, args.location, args.username)

    if password is None and notes is None:
        sys.stdout.write('No password found.')
        selection = input('Should I generate a random password? (Y/n)').strip()
        if len(selection)==0 or selection[0].lower()=='y':
            password = dbutil.generate_password_and_save(conn, key, args.location, args.username, 16)
        else:
            password = None
    elif password is None:
        sys.stdout.write('No password found.')
        selection = input('Should I generate a random password? (Y/n)').strip()
        if len(selection)==0 or selection[0].lower()=='y':
            password = dbutil.generate_password_and_overwrite(conn, key, args.location, args.username, 16)
        else:
            password = None


    sys.stdout.write('Location: %s\n'%(args.location))
    sys.stdout.write('Username: %s\n'%(args.username))
    if password is not None:
        place_in_clipboard(password)
        sys.stdout.write('Placed password in clipboard\n')
    else:
        sys.stdout.write('No password found or generated\n')

    return 0

def place_in_clipboard(text):
    platform_system = platform.system()

    if platform_system=='Darwin':
        # OS X
        p = subprocess.Popen('pbcopy', env={'LANG': 'en_US.UTF-8'}, stdin=subprocess.PIPE)
        p.communicate(text.encode('UTF-8'))

    else:
        raise NotImplementedError('The platform %s is not implemented'%(platform_system))

if __name__=='__main__':
    sys.exit(main())
