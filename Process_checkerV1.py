__author__ = "azertyui"
__date__ = "20/01/2"
__version__ = "1.0"
__maintainer__ = "azertyui"

from datetime import datetime
from locale import LC_ALL
import os.path
import sys
import psutil
import subprocess

lnetworkconnection = []
dWhiteList = {}
dGrelist_to_try = {}
dDifference_pid = {}

subprocess.call(["clear"])


def main():  
    menu()


def menu():
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
                      E: Verification of evil Process/Hash 
                      R: Verification of evil Process using network
                      T: MAGIC
                      Y: Leave

                      Please make a choice: """)

    if choice.lower() == "a":
        creation_liste_blanche()
    elif choice.lower() == "z":
        creation_liste_grise()
    elif choice.lower() == "e":
        verification_malveillant()
    elif choice.lower() == "r":
        check_reseau()
    elif choice.lower() == "t":
        export_resultat()
    elif choice.lower() == "y":
        sys.exit
    else:
        print("You have to choose beetween A, Z, E, R, T ou Y !")
        print("Try again !")
        menu()  # or main ?


def creation_liste_blanche():
    # Verifier si le fichier existe ou non
    if os.path.isfile('Process_Hash.txt'):
        print()
        print("WHITE list is already present !")
        print()
        menu()
    else:
        subprocess.call(['./Creation_list.sh'])
        print()
        print("Creation of WHITE list  -> OK !")
        print()
        print()
        menu()


def creation_liste_grise():
    # Verifier si le fichier existe ou non
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


def export_resultat():
    global dGrelist_to_try
    global dWhiteList
    global dDifference_pid
    global lnetworkconnection

    print()
    print("Export in progress ...")
    print("Exporting to Investigation.csv  -> OK !")

    with open('Investigation.csv', 'a') as Investigation:
        for process, hash in dGrelist_to_try.items():
            if process not in dWhiteList.keys():
                print("Suspect PROCESS  found ! ! ! ", process,
                "--- HASH of suspect PROCESS:", hash, "DATE:",
                datetime.today(), file=Investigation)

    with open('Investigation.csv', 'a') as Investigation:
        for process, hash in dGrelist_to_try.items():
            if hash not in dWhiteList.values():
                print("Suspect HASH  found ! ! ! ", hash,
                "--- PROCESS of suspect HASH:", process, "DATE:",
                datetime.today(), file=Investigation)

    with open('Investigation.csv', 'a') as Investigation:
        for pid in lnetworkconnection:
            if str(pid.pid) in dDifference_pid.keys():
                print("The Process", dDifference_pid[str(pid.pid)], "pid:",
                    pid.pid, " is using Network", pid.laddr, pid.raddr,
                    pid.status, pid.type, "LINK:", datetime.today(),
                    file=Investigation)

    menu()


def verification_malveillant():
    global dGrelist_to_try
    global dWhiteList

    if os.path.isfile('Process_Hash_grey.txt'):

        # Generation lsit & Dictionnaire liste blanche
        dWhiteList = {}
        vFiletoparsewhite = open("Process_Hash.txt")
        for line in vFiletoparsewhite:
            pid, proc, hash = line.split()  # Separateur un espace
            dWhiteList[proc] = hash

        # Generation list & Dictionnaire liste grise
        dGrelist_to_try = {}
        vFiletoparseGrey = open("Process_Hash_grey.txt")
        for line in vFiletoparseGrey:
            pid, proc, hash = line.split()  # Separateur un espace
            dGrelist_to_try[proc] = hash
        #boucle comparaison

        for process, hash in dGrelist_to_try.items():
            if process not in dWhiteList.keys():
                print("Suspect PROCESS  found ! ! ! ", process, "--- HASH \
                    of suspect PROCESS :", hash, "DATE:", datetime.today())

        print()
        print()

        for process, hash in dGrelist_to_try.items():
            if hash not in dWhiteList.values():
                print("Suspect HASH found ! ! ! ", hash, "--- PROCESS \
                suspect:", process, "DATE:", datetime.today())     
        menu()
    else:
        print()
        print("Create GREY list first ! ! !")
        print()
        print()
        menu()


def check_reseau():
    dGrelist_to_try_pid = {}
    dWhitelist_to_try_pid = {}
    global lnetworkconnection
    global dDifference_pid
#    #Generation dico avec le PID
    vFiletoparse_grey_pid = open("Process_Hash_grey.txt")
    for line in vFiletoparse_grey_pid:
        key, value, hash = line.split()  # Separateur un espace
        dGrelist_to_try_pid[key] = value

    vFiletoparse_white_pid = open("Process_Hash.txt")
    for line in vFiletoparse_white_pid:
        key, value, hash = line.split()  # Separateur un espace
        dWhitelist_to_try_pid[key] = value

    for pid, process in dGrelist_to_try_pid.items():
        if process not in dWhitelist_to_try_pid.values():
            dDifference_pid.update({pid: process})

    lnetworkconnection = psutil.net_connections()
    for pid in lnetworkconnection:
        if str(pid.pid) in dDifference_pid.keys():
            print("The Process", dDifference_pid[str(pid.pid)], "pid:",
                pid.pid, " is using Network", pid.laddr[0], pid.laddr[1],
                pid.raddr, pid.type, "LINK:", pid.status)
    print()
    menu()


if __name__ == '__main__':
    main()