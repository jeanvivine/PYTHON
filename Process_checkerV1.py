'''Comparison of process with a given WHITELIST in order to
    determine if it's a malicious one.

Usage:
======
    Root needed.
    Python3.10
    pip3.10 install -r requirements.txt
    Process_checkerV1.py & Creation_list.sh have to be in the same folder.
    python3.10 Process_checker.py

'''

__author__ = "Jeanvivine"
__date__ = "20/01/2022"
__version__ = "1.0"
__maintainer__ = "Jeanvivine"

from datetime import datetime
from locale import LC_ALL
import os.path
import sys
import psutil
import subprocess

lNetworkconnection = []
dWhitedict = {}
dGreytotry = {}
dDifferencepid = {}

subprocess.call(["clear"])


def menu():
    """Print the menu.
    If the choice is not AZERTY, recall menu().
    Uppercase to lowercase.
    Y to leave the program.
    """
    print("""
            ******************Welcome to Process_Checker******************

                                        .-------.
                                        | -----.-----.
                                        | -----| ----|\\
                                        | -----| ----- |
                                        | -----| ----- |
                                        '------| ----- |
                                         JV    '-------'
             ***************************************************************
                                    Creation_list.sh
                            have to be in the same folder !""")
    print()
    print()
    choice = input("""
                      A: Creation of WHITE list
                      Z: Creation of GREY list
                      E: Verification of malicious Process/Hash
                      R: Verification of malicious Process using network
                      T: MAGIC
                      Y: Leave

                      Please make a choice: """)

    if choice.lower() == "a":
        create_white_list()
    elif choice.lower() == "z":
        create_grey_list()
    elif choice.lower() == "e":
        check_malicious_items()
    elif choice.lower() == "r":
        check_network()
    elif choice.lower() == "t":
        export_results()
    elif choice.lower() == "y":
        sys.exit
    else:
        print("You have to choose beetween A, Z, E, R, T ou Y !")
        print("Try again !")
        menu()


def create_white_list():
    '''Verify if the file is in the current directory.
    If present return to menu.
    If not present create the WHITE list Process_Hash.txt
    '''

    if os.path.isfile('Process_Hash.txt'):  # File in the current directory?
        print()
        print("WHITE list is already present !")
        print()
        menu()
    else:
        subprocess.call(['./Creation_list.sh'])  # No file? launch the script!
        print()
        print("Creation of WHITE list  -> OK !")
        print()
        print()
        menu()


def create_grey_list():
    '''Verify if the file is in the current directory.
    If present return to menu.
    If not present create the GREY list Process_Hash_grey.txt
    '''

    if os.path.isfile('Process_Hash_grey.txt'):
        print()
        print("GREY list is already present !")
        print()
        menu()
    else:
        subprocess.call(['./Creation_list.sh'])
        print()
        print("Creation of GREY list  -> OK !")
        print()
        print()
        menu()


def export_results():
    '''Export all the results in Investigation.csv with a timestamp.
    Then return to menu.
    '''

    global dGreytotry
    global dWhitedict
    global dDifferencepid
    global lNetworkconnection

    print()
    print("Export in progress ...")
    print("Exporting to Investigation.csv  -> OK !")

    with open('Investigation.csv', 'a') as Investigation:
        # Opening the file to write
        for process, hash in dGreytotry.items():
            # dictionnay with process and hash
            if process not in dWhitedict.keys():
                # if the process is not in dWhitedict dictionnary
                # write it in Investigation.csv
                print("Suspect PROCESS  found ! ! ! ", process,
                      "--- HASH of suspect PROCESS:", hash, "DATE:",
                      datetime.today(), file=Investigation)

    with open('Investigation.csv', 'a') as Investigation:
        # Opening the file to write
        for process, hash in dGreytotry.items():
            # dictionnay with process and hash
            if hash not in dWhitedict.values():
                # if the Hash is not in dWhitedict dictionnary
                # write it in Investigation.csv
                print("Suspect HASH  found ! ! ! ", hash,
                      "--- PROCESS of suspect HASH:", process, "DATE:",
                      datetime.today(), file=Investigation)

    with open('Investigation.csv', 'a') as Investigation:
        # Opening the file to write
        for pid in lNetworkconnection:
            # dictionnay with process and hash
            if str(pid.pid) in dDifferencepid.keys():
                # If pid number is in the dictionnary
                # write it in Investigation.csv
                print("The Process", dDifferencepid[str(pid.pid)], "pid:",
                      pid.pid, " is using Network", pid.laddr, pid.raddr,
                      pid.status, pid.type, "LINK:", datetime.today(),
                      file=Investigation)

    menu()


def check_malicious_items():
    '''Creation of the dictionnary WHITE/GREY list.
    Comparison of WHITE and GREY list.
    If there is a difference print the malicious Process/Hash.
    '''

    global dGreytotry
    global dWhitedict

    if os.path.isfile('Process_Hash_grey.txt'):  # If the file is here.

        # Creation of Dictionnary WHITElist
        dWhitedict = {}
        vFiletoparsewhite = open("Process_Hash.txt")
        for line in vFiletoparsewhite:  # For everyline in Process_Hash
            pid, proc, hash = line.split()  # Separator space
            dWhitedict[proc] = hash  # Key is proc and value is the Hash

        # Creation of Dictionnary GREYlist
        dGreytotry = {}
        vFiletoparseGrey = open("Process_Hash_grey.txt")
        for line in vFiletoparseGrey:  # For everyline in Process_Hash_grey
            pid, proc, hash = line.split()  # Separator space
            dGreytotry[proc] = hash  # Key is proc and value is the Hash
        # Comparison loop
        for process, hash in dGreytotry.items():  # For items in dict
            if process not in dWhitedict.keys():
                print("Suspect PROCESS  found ! ! ! ", process, "--- HASH \
of suspect PROCESS :", hash, "DATE:", datetime.today())

        print()
        print()
        # Comparison loop
        for process, hash in dGreytotry.items():
            if hash not in dWhitedict.values():
                print("Suspect HASH found ! ! ! ", hash, "--- PROCESS \
suspect:", process, "DATE:", datetime.today())
        menu()
    else:
        print()
        print("Create GREY list first ! ! !")
        print()
        print()
        menu()


def check_network():
    '''Creation of the dictionnary with the PID.
    Comparison of WHITE and GREY list.
    If PID is in dDifferencepid, check his network status and display it.
    '''
    dGreytotry_pid = {}
    dWhitedict_to_try_pid = {}
    global lNetworkconnection
    global dDifferencepid

    if os.path.isfile('Process_Hash_grey.txt'):  # If the file is here.
        # Creation of dictionnaries with PID
        vFiletoparse_grey_pid = open("Process_Hash_grey.txt")
        for line in vFiletoparse_grey_pid:
            proc, pid, hash = line.split()  # Separator space
            dGreytotry_pid[proc] = pid  # Key is proc and value is the PID

        vFiletoparse_white_pid = open("Process_Hash.txt")
        for line in vFiletoparse_white_pid:
            proc, pid, hash = line.split()  # Separator space
            dWhitedict_to_try_pid[proc] = pid  # Key is proc and value is PID
        # Comparison loop
        for pid, process in dGreytotry_pid.items():
            if process not in dWhitedict_to_try_pid.values():
                dDifferencepid.update({pid: process})  # Update the dictionnary

        lNetworkconnection = psutil.net_connections()  # Psutil result in list
        for pid in lNetworkconnection:
            if str(pid.pid) in dDifferencepid.keys():
                # If pid number is in the dictionnary
                # Display it
                print("The Process", dDifferencepid[str(pid.pid)], "pid:",
                      pid.pid, " is using Network", pid.laddr[0], pid.laddr[1],
                      pid.raddr, pid.type, "LINK:", pid.status)

        print()
        menu()
    else:
        print()
        print("Create GREY list first ! ! !")
        print()
        print()
        menu()


if __name__ == '__main__':
    menu()
