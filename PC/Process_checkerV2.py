"""
Commentaire a mettre !

"""
from datetime import datetime
from locale import LC_ALL
import os.path
import sys
import psutil
import subprocess

lconnectionreseau = []
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
            Assurez-vous d'avoir positionne le fichier Creation_list.sh 
                               dans le meme repertoire !""")

    print()

    choice = input("""
                      A: Creation de la liste BLANCHE
                      Z: Creation de la liste GRISE
                      E: Verification de Process/Hash malveillant
                      R: Verification des Process malveillant avec Reseau
                      T: Magic
                      Y: Quitter

                      Merci d'entrer un choix: """)

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
        print("Vous devez choisir entre A, Z, E, R, T ou Y !")
        print("Try again !")
        menu()  # ou main ?
# A voir si cela est pertinent La regenerer a chaque appel semble pertinenet


def creation_liste_blanche():
    # Verifier si le fichier existe ou non
    if os.path.isfile('Process_Hash.txt'):
        print()
        print("La liste blanche est deja presente !")
        print()
        menu()
    else:
        subprocess.call(['./Creation_list.sh'])
        print()
        print("Creation de la liste BLANCHE  -> OK !")
        print()
        print()
        menu()


def creation_liste_grise():
    # Verifier si le fichier existe ou non
    if os.path.isfile('Process_Hash_grey.txt'):
        print()
        print("La liste grise est deja presente !")
        print()
        menu()
    else:
        subprocess.call(['./Creation_list.sh'])
        print()
        print("Creation de la liste GRISE  -> OK !")
        print()
        print()
        menu()

def export_resultat():
    global dGrelist_to_try
    global dWhiteList
    global dDifference_pid
    global lconnectionreseau

    print()
    print("Export en cours ...")
    print("Export vers Investigation.csv  -> OK !")



    with open('Investigation.csv', 'w') as Investigation:
        for process, hash in dGrelist_to_try.items():
            if process not in dWhiteList.keys():
                print("PROCESS suspect detecte ! ! ! ", process,
                "--- HASH du process suspect:", hash, "DATE:",
                datetime.today(), file=Investigation)

    with open('Investigation.csv', 'w') as Investigation:
        for process, hash in dGrelist_to_try.items():
            if hash not in dWhiteList.values():
                print("HASH suspect detecte ! ! ! ", hash,
                "--- PROCESS suspect:", process, "DATE:",
                datetime.today(), file=Investigation)

    with open('Investigation.csv', 'w') as Investigation:
        for pid in lconnectionreseau:
            if str(pid.pid) in dDifference_pid.keys():
                print("Le Process", dDifference_pid[str(pid.pid)], "pid:", pid.pid,
                      " utilise le reseau", pid.laddr, pid.raddr, pid.status,
                      pid.type, "DATE:", datetime.today(),
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
                print("PROCESS suspect detecte ! ! ! ", process, "--- HASH \
du process suspect:", hash, "DATE:", datetime.today())

        print()
        print()

        for process, hash in dGrelist_to_try.items():
            if hash not in dWhiteList.values():
                print("HASH suspect detecte ! ! ! ", hash, "--- PROCESS \
suspect:", process, "DATE:", datetime.today())     
        menu()
    else:
        print()
        print("Merci de proceder a la creation de la creation de la liste \
GRISE au prealable !")
        print()
        print()
        menu()

def check_reseau():
    dGrelist_to_try_pid = {}
    dWhitelist_to_try_pid = {}
    global lconnectionreseau
    global dDifference_pid

    #Generation dico avec le PID
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

    lconnectionreseau = psutil.net_connections()
    for pid in lconnectionreseau:
        if str(pid.pid) in dDifference_pid.keys():
            print("Le Process", dDifference_pid[str(pid.pid)], "pid:", pid.pid,
                  " utilise le reseau", pid.laddr[0], pid.laddr[1], pid.raddr, pid.type, "LIEN:", pid.status)
    print()
    menu()


if __name__ == '__main__':
    main()
