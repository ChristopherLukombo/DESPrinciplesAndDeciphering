from Des import *
from FileProvider import *

des = Des()
file_provider = FileProvider()

if __name__ == "__main__":
    import sys

files = des.get_list_files(sys.argv[1])

i = 1
for encryption_key in files:
    print('Tapez ' + str(i) + ' pour appliquer le chiffrement pour le fichier ' + files[
        encryption_key] + ' et la clé : ' + encryption_key)
    i += 1

choice = 0

ciphers = dict()

while -1 != choice:

    try:
        choice = int(input("Choix :"))

        if 1 <= choice < i:
            encryption = file_provider.read_file(sys.argv[1] + des.get_chiffrement(files, choice))
            encryption_key = file_provider.read_file(sys.argv[1] + des.get_key(choice))
            encrypted_message = des.cipher(encryption, encryption_key)
            print("Message encrypté :")
            print(des.binary_to_text(encrypted_message))
            print("--------------------------------------------------------------------------------------------------")
            print("--------------------------------------------------------------------------------------------------")
            if encryption_key not in ciphers:
                ciphers[encryption_key] = encrypted_message

            decrypted_message = des.decipher(encrypted_message, encryption_key)

            print("Message décrypté :")
            print(decrypted_message)

            print("--------------------------------------------------------------------------------------------------")
            print("--------------------------------------------------------------------------------------------------")
        else:
            print("Le choix doit être compris entre 1 et " + str(i - 1))

        if len(ciphers) > 0:
            i = 1
            for encryption_key in files:
                print('Tapez ' + str(i) + ' pour appliquer le chiffrement pour le fichier ' + files[
                    encryption_key] + ' et la clé : ' + encryption_key)
                i += 1
    except ValueError as e:
        print("Veuillez entrer un nombre valide")
