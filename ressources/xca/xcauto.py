from pywinauto.application import Application
from os import path, remove, getcwd
from json import loads, dumps
from sys import argv

database_name = None
database_password = None

CA_private_keys = None
CA_certificates = None

certificates = None

models = None


def delete_existing_database():

    global database

    if path.exists(database):

        print("  Deleting existing database")
        remove(database)


def initialize_database_password():

    print("  Enter database password")

    global database_password
    global XCA

    XCA.NouveauMotDePasse.type_keys(database_password)
    XCA.NouveauMotDePasse.type_keys("{TAB}")
    XCA.NouveauMotDePasse.type_keys(database_password)
    XCA.NouveauMotDePasse.type_keys("{ENTER}")


def import_authorities():

    global XCA
    global window

    for CA_certificate in CA_certificates:

        sequence = [
            {"select_tab": ["Certificats"]},
            {"click": ["Importer"]}
        ]

        eval_sequence(sequence)

        path = "/".join(CA_certificate.split('/')[:-1])
        name = CA_certificate.split('/')[-1]

        window.ImporterUnCertificatX509Dialog.type_keys(f'%a^a{path}~', with_spaces=True)

        sequence = [
            {"double_click": [name]},
            {"click": ["OK"]},
        ]

        eval_sequence(sequence)

    for CA_private_key in CA_private_keys:

        sequence = [
            {"select_tab": ["Clés privés"]},
            {"click": ["Importer"]}
        ]

        eval_sequence(sequence)

        path = "/".join(CA_private_key.split('/')[:-1])
        name = CA_private_key.split('/')[-1]

        window.ImporterUnCertificatX509Dialog.type_keys(f'%a^a{path}~', with_spaces=True)

        sequence = [
            {"double_click": [name]},
            {"click": ["OK"]}
        ]

        eval_sequence(sequence)


def start_xca():

    global XCA
    global window

    delete_existing_database()

    # https://hohnstaedt.de/xca-doc/html/database.html#database-schema

    program_path = '\\'.join(path.realpath(__file__).split('\\')[:-1]) + "\\xca-portable-2.4.0\\xca.exe"

    # DEMARRER L'APPLICATION
    XCA = Application(backend="uia").start(f'"{program_path}" --database="{database}"')

    initialize_database_password()

    window = XCA.connect(title="X Certificate and Key management", timeout=20).XCertificateAndKeyManagement

    # ATTENDRE QUE L'APPLICATION SOIT LANCÉE
    window.wait('ready')

    # METTRE L'APPLICATION EN GRAND ECRAN
    window.wrapper_object().maximize()


def exit_xca():

    select("Fichier", "Quitter")


def title_format(string):

    # Enlève les caractère accentués
    string = string.translate(string.maketrans("àâäÀÂÄéèêëÉÈÊËîïìÌÎÏòôöÒÔÖùûüÙÛÜç", "aaaAAAeeeeEEEEiiiIIIoooOOOuuuUUUc")) 

    # Enlève les espaces, ajouter une majuscule au debut de chaque mot et ajouter "Edit" à la fin
    return string.title().replace(" ", "")


def click(buttons_name, button_type="Button", double=False, right=False):

    if type(buttons_name) != list:
        buttons_name = [buttons_name]

    print("click(" + str(buttons_name) + ", " + button_type + ")")

    for button_name in buttons_name:

        window.wait('ready')

        # Définit le nom du bouton à cliquer
        button_name = title_format(button_name) + button_type

        if right:            
            # Clique sur le bouton
            window[button_name].wrapper_object().RightClickInput()

        else:
            # Clique sur le bouton
            window[button_name].wrapper_object().click_input(double=double)


def right_click(buttons_name):

    print("right_click(" + str(buttons_name) + ")")

    click(buttons_name, right = True)


def double_click(buttons_name, button_type="Button"):

    print("double_click(" + str(buttons_name) + ")")

    click(buttons_name, button_type=button_type, double = True)


def fill(input_name, text):

    print("fill(" + input_name + ", " + text + ")")

    click(input_name, "Edit")

    # Sélectionne tout avec un Ctrl+a
    # https://pywinauto.readthedocs.io/en/latest/code/pywinauto.keyboard.html
    window.XCertificateAndKeyManagement.type_keys("^a^x" + text, with_spaces = True)


def select_tab(tabs_name):

    print("select_tab(" + str(tabs_name) + ")")

    click(tabs_name, "TabItem")


def active(items_name):

    print("active(" + str(items_name) + ")")

    click(items_name, "ListItem")


def select(list_name, items_name):

    if type(items_name) != list:
        items_name = [items_name]

    print("select(" + list_name + ", " + str(items_name) + ")")

    click(list_name, "ComboBox")

    for item_name in items_name:
        active(item_name)


def switch(radio_buttons_name):

    print("switch(" + str(radio_buttons_name) + ")")

    click(radio_buttons_name, "RadioButton")


def check(boxes_name):

    print("check(" + str(boxes_name) + ")")

    click(boxes_name, "CheckBox")


def eval_sequence(actions):

    for action in actions:
        for action_type, action_values in action.items():

            if type(action_values[0]) == dict:

                for action_value in action_values:
                    for key, value in action_value.items():
                        eval(f'{action_type}("{key}", "{value}")')

            else:

                eval(f'{action_type}({action_values})')


def export_certificates(certificates):

    sequence = [
        {"select_tab": ["Certificats"]},
        {"click": ['VueAPlat']}
    ]

    eval_sequence(sequence)

    sequence = []

    for certificat in certificates:

        sequence += [
            {"click": [certificat["name"], "Exporter"]},
            {"select": [{"Format d'exportation": "Chaîne en PEM (*.pem)"}]},
            {"fill": [{"Nom du fichier": certificat["certificate_export_path"]}]},
            {"click": ["OK"]}
        ]

    eval_sequence(sequence)


def export_private_keys(certificates):

    sequence = []

    for certificat in certificates:

        sequence += [
            {"select_tab": ["Clés privées"]},
            {"click": [certificat["name"], "Exporter"]},
            {"fill": [{"Nom du fichier": certificat["private_key_export_path"]}]},
            {"click": ["OK"]}
        ]

    eval_sequence(sequence)


def create_certificates(certificates):

    for certificat in certificates:

        sequence = [
            {"select_tab": [
                "Certificats"
            ]},
            {"click": [
                "Nouveau certificat"
            ]},
            {"switch": [
                "Utiliser ce certificat pour signer"
            ]},
            {"select": [
                {"Signer": certificat["CA"]}, 
                {"Algorithme de signature": "SHA 512"},
                {"Modèle pour le nouveau certificat": certificat["model"]}
            ]},
            {"click": [
                "Appliquer tout"
            ]},
            {"select_tab": [
                "Sujet"
            ]},
            {"fill": [
                {"Nom interne": certificat["name"]},
                {"Nom commun": certificat["name"]}
            ]},
            {"click": [
                "Générer une nouvelle clé"
            ]}
        ]

        eval_sequence(sequence)

        # La fonction "select" ne fonctionne pas pour le champs "Taille de la clé". 
        # Ce champs est différent des autres champs "combobox" (on peut le voir par la couleur du fond qui est blanche et non grise)
        #
        # La fonction "fill" ne fonctionne pas pour le champs "Taille de la clé". 
        # Car le nom de la fenêtre n'est pas "XCertificateAndKeyManagement", comme par défaut dans la fonction "fill", mais "TailleDeLaCleEdit"
        #
        window.TailleDeLaCleEdit.type_keys("^a^x4096 bit", with_spaces=True)

        sequence = [
            {"click": [
                "Créer", 
                "OK"
            ]},
            {"select_tab": [
                "Extensions"
            ]},
            {"fill": [
                {"X509v3 Subject Alterative Name": certificat["subject_alternative_names"]}
            ]},
            {"click": [
                "OK", 
                "Continuer le déploiement", 
                "OK"
            ]},
        ]

        eval_sequence(sequence)


def create_models(models):

    sequence = []

    for model in models:

        sequence += [
            {"select_tab": ["Modèles"]},
            {"click": ["Nouveau Modèle", "OK"]},
            {"select_tab": ["Sujet"]},
            {"fill": [
                {"Nom interne": model["name"]},
                {"Country name": model["CountryName"]},
                {"organizationName": model["OrganizationName"]},
                {"organizationalUnitName": model["OrganizationalUnitName"]},
                {"commonName": model["CommonName"]}
            ]},
            {"select_tab": ["Extensions"]},
            {"fill": [{"X509v3 Subject Alterative Name": model["SubjectAlternativeName"]}]},
            {"select": [
                {"X509v3 Basic Constraints": model["BasicConstraintsType"]},
                {"Intervalle de temps": model["ExpirationUnit"]}
            ]},
            {"check": model["ExtensionsCheckboxes"],
             },
            {"fill": [
                {"Edit2": model["Expiration"]}
            ]},
            {"select_tab": ["Usage de la clé"]},
            {"check": model["UsageCheckboxes"]},
            {"active": model["KeyUsage"] + model["ExtendedKeyUsage"]},
            {"select_tab": ["Netscape"]},
            {"active": model["NetscapeCertType"]},
            {"fill": [
                {"Netscape Comment": ""}
            ]},
            {"click": [
                "OK",
                "OK"
            ]}
        ]

        eval_sequence(sequence)


def main(data):

    global database_name
    global database
    global database_password
    global CA_private_keys
    global CA_certificates
    global certificates
    global models

    print("                                          ")
    print("  __  ______    _         _               ")
    print("  \\ \\/ / ___|  / \\  _   _| |_ ___      ")
    print("   \\  / |     / _ \\| | | | __/ _ \\     ")
    print("   /  \\ |___ / ___ \\ |_| | || (_) |     ")
    print("  /_/\\_\\____/_/   \\_\\__,_|\\__\\___/  ")
    print("                                          ")

    data = loads(data)

    database_path = data["database"].split("/").pop()
    database_name = data["database"].split("/")[-1]
    database = data["database"]
    database_password = data["database_password"]
    CA_private_keys = data["CA_private_keys"]
    CA_certificates = data["CA_certificates"]
    certificates = data["certificates"]
    models = data["models"]

    start_xca()
    import_authorities()
    create_models(models)
    create_certificates(certificates)
    export_certificates(certificates)
    export_private_keys(certificates)
    exit_xca()


main(argv[1])


# Application.XCertificateAndKeyManagement.print_control_identifiers()
