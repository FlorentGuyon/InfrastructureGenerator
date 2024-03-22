from pathlib import Path
from os import mkdir, listdir, getcwd
from shutil import copyfile, rmtree, copytree
from datetime import datetime
from json import dumps, loads
from random import sample
from subprocess import Popen, PIPE
from sys import argv

##
# Create one by one the folders of a path :
# 
# path = etc/sysconfig/network-scripts
# 
# mkdir(etc)
# mkdir(etc/sysconfig)
# mkdir(etc/sysconfig/network-scripts)
# 


def recursive_mkdir(path):

    #
    # translate a linux-style path to a windows-style path
    # "hostname/tree/etc/ssh/sshd_config" -> "hostname\tree\etc\ssh\sshd_config"
    #
    path = path.replace('/', '\\')

    #
    # ["hostname", "tree", "etc", "ssh"] = "hostname/tree/etc/ssh/sshd_config"
    # It removes the last part ; the file
    #
    folders = path.split('\\')[:-1]
    path = ""

    for folder in folders:
        # "" -> "hostname/" -> "hostname/tree/" -> "hostname/tree/etc/" -> "hostname/tree/etc/ssh/"
        path += folder + '/'

        if not Path(path).is_dir():
            mkdir(path)
            print("Create:\t", path)

##
# Copy a file without changes
#


def copy_file(source, dest=None):

    if dest is None:
        dest = source

    dest = dest.replace("ressources", f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}')

    recursive_mkdir(dest)

    copyfile(source, dest)
    print("Copy:\t", dest, '\n')

##
# Copy recursively a tree without changes
#


def copy_tree(source, dest=None):

    if dest is None:
        dest = source

    dest = dest.replace("ressources", f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}')

    recursive_mkdir(dest)

    copytree(source, dest, dirs_exist_ok=True)
    print("Copy:\t", dest, '\n')

##
# Append the content of the "data" variable in the "dest" file
#


def append_to_file(dest, data):

    recursive_mkdir(dest)

    with open(dest, "a", errors = "ignore", encoding = 'utf8', newline = '\n') as fd:
        print("Open:\t", dest)

        fd.write(data)
        print("Append:\t", data, '\n')

##
# Replace the content of the "dest" file with the content of the "data" variable
#


def overwrite_file(dest, data):

    recursive_mkdir(dest)

    with open(dest, "w", errors = "ignore", encoding = 'utf8', newline = '\n') as fd:
        print("Open:\t", dest)

        fd.write(data)
        print("Overwrite:\t", data, '\n')

# 
# Replace a key to its value in a source file :
# 
# source = etc/ssh/sshd_config
# 
# data = {
#   "[ssh_listening_address]": "10.0.0.10", 
#   ...
# }
# 
# File :
# "...
# ListenAddress [ssh_listening_address]
# ..."
# 
# "...
# ListenAddress 10.0.0.10
# ..."
#


def configure_file(source, data={}, dest=None, encoding="utf-8"):
    print("Read:\t", source)

    if dest is None:
        dest = source

    with open(source, "r", errors = "ignore", encoding = encoding, newline = '\n') as fd:
        content = fd.read()

        for key, value in data.items():
            if key in content:
                value = value.strip()
                content = content.replace(key, value)
                print("Update:\t", key, " ---> ", value.replace('\n', '\n\t '))

        dest = str(dest).replace("ressources", f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}')

        recursive_mkdir(dest)

        with open(dest, "w", encoding = encoding, newline = '\n') as fd2:
            fd2.write(content)
            print("Write:\t", dest, '\n')


for arg_id, arg in enumerate(argv):

    if arg in ["-o", "--output"]:
        configuration_dest_path = argv[arg_id + 1]

#
# Eeach folder in the "sites" directory represents a site ready to be configured 
#
available_configurations = listdir("configurations/")
configuration_count = 0

print("Sites disponibles:\n")
print(" 0 - TOUT")

for current_configuration_id, current_configuration in enumerate(available_configurations):
    print(f' {current_configuration_id + 1} - {current_configuration}')
    configuration_count += 1

chosen_configuration_id = 0
list_not_valid = True

while list_not_valid:

    chosen_configuration_id = input(f'\nEntrer l\'identifiant des sites à préparer: ')

    try:
        chosen_configuration_id_list = [int(chosen_configuration_id) for chosen_configuration_id in chosen_configuration_id.split()]
        list_not_valid = False

        for chosen_configuration_id in chosen_configuration_id_list:
            if chosen_configuration_id not in range(0, configuration_count + 1):
                list_not_valid = True
                break
    except:
        pass

chosen_configuration_name_list = []

if chosen_configuration_id_list == [0]:
    chosen_configuration_name_list = available_configurations

else:
    for chosen_configuration_id in chosen_configuration_id_list:
        chosen_configuration_name_list.append(available_configurations[chosen_configuration_id - 1])

for chosen_configuration_name in chosen_configuration_name_list:

    if "hosts" in listdir(f'./configurations/{chosen_configuration_name}'):

        print(f'\nSuppression de l\'anciene génération du site {chosen_configuration_name}...')
        rmtree(f'./configurations/{chosen_configuration_name}/hosts')

    host_list = None
    host_file = f'./configurations/{chosen_configuration_name}/hosts.json'

    print(f'Chargement de la configuration du site {chosen_configuration_name}...')

    with open(host_file, encoding='utf8') as fd:

        content = fd.read()
        host_list = loads(content)

    print(f'\nConfiguration du site {chosen_configuration_name}:\n\n{host_list}')

    #
    # For each hostname, create an installation script with a custom tree
    #
    # <hostname>
    #  |_tree
    #  | |_etc
    #  |   |_ssh
    #  |   | |_sshd_config
    #  |   |_...
    #  |_centos.sh
    #

    for hostname, data in host_list.items():

        if "domain" in data.keys(): 
            domain = data["domain"]

        #
        #####################################  X C A  #######################################
        #

        if data["os"] == "centos":

            if "xca" in data.keys():

                current_absolute_path = getcwd().replace("\\", "/")

                copy_file("ressources/tree/usr/local/bin/xca")

                CA_certificate_path = []
                CA_private_key_path = []

                for CA_certificate in data["xca"]["CA_certificates"]:
                    copy_file(f'{current_absolute_path}/ressources/certificates/{CA_certificate}', f'configurations/{chosen_configuration_name}/xca/certificates/{CA_certificate}')
                    CA_certificate_path.append(f'{current_absolute_path}/ressources/certificates/{CA_certificate}')

                for CA_private_key in data["xca"]["CA_private_keys"]:    
                    copy_file(f'{current_absolute_path}/ressources/certificates/{CA_private_key}', f'configurations/{chosen_configuration_name}/xca/private_keys/{CA_private_key}')
                    CA_private_key_path.append(f'{current_absolute_path}/ressources/certificates/{CA_private_key}')

                database_name = domain.replace(".", "_") + "_xca_database.xdb"
                database_path = f'{current_absolute_path}/configurations/{chosen_configuration_name}/xca/database/{database_name}'

                database_password = data["xca"]["database_password"] if "database_password" in data["xca"].keys() else ""

                models = []

                for new_model in data["xca"]["models"]:

                    model = {
                        "CommonName": "<hostname>.<domain>",
                        "BasicConstraintsType": "Entit\u00c3\u00a9 Finale",
                        "Expiration": "20",
                        "ExpirationUnit": "Ann\u00c3\u00a9es",
                        "SubjectAlternativeName": "IP:1.1.1.1,DNS:fqdn",
                        "ExtensionsCheckboxes": [
                            "Critical",
                            "X509v3 Subject Key Identifier"
                        ],
                        "KeyUsage": [
                            "Digital Signature",
                            "Non Repudiation",
                            "Key Encipherment"
                        ],
                        "UsageCheckboxes": [
                            "Critical"
                        ],
                        "ExtendedKeyUsage": [
                            "TLS Web Server Authentication"
                        ],
                        "NetscapeCertType": [
                            "SSL Client",
                            "SSL Server"
                        ]   
                    }

                    model["name"] = new_model["name"] if "name" in new_model.keys() else ""
                    model["CountryName"] = new_model["country_name"] if "country_name" in new_model.keys() else ""
                    model["OrganizationName"] = new_model["organization_name"] if "organization_name" in new_model.keys() else ""
                    model["OrganizationalUnitName"] = new_model["organizational_unit_name"] if "organizational_unit_name" in new_model.keys() else ""

                    models.append(model)

                recursive_mkdir(database_path)

                if not Path(database_path).is_file():

                    xca_data = {
                        "database": database_path,
                        "database_password": database_password,
                        "CA_private_keys": CA_private_key_path,
                        "CA_certificates": CA_certificate_path,
                        "models": models,
                        "certificates": []
                    }

                    for hostname2, data2 in host_list.items():
                        if "domain" in data2.keys() and domain == data2["domain"]: 
                            if "certificate" in data2.keys():

                                ca = data2["certificate"]["ca"]
                                model = data2["certificate"]["model"]
                                name = hostname2
                                certificates_path = f'{current_absolute_path}/configurations/{chosen_configuration_name}/xca/certificates/{name}.crt'
                                private_keys_path = f'{current_absolute_path}/configurations/{chosen_configuration_name}/xca/private_keys/{name}.key'

                                subject_alternative_names = []

                                if "network" in data2.keys():
                                    for card in data2["network"].values():
                                        if "dns_name" in card.keys():
                                            subject_alternative_name = f'DNS:{card["dns_name"]}'
                                            subject_alternative_names.append(subject_alternative_name)

                                        if ("interface" in card.keys()) and ("address" in card["interface"].keys()):
                                            subject_alternative_name = f'IP:{card["interface"]["address"]}'
                                            subject_alternative_names.append(subject_alternative_name)

                                subject_alternative_names = ",".join(subject_alternative_names)

                                xca_data["certificates"].append({
                                    "CA": ca, 
                                    "model": model, 
                                    "name": name,
                                    "certificate_export_path": certificates_path,
                                    "private_key_export_path": private_keys_path,
                                    "subject_alternative_names": subject_alternative_names
                                })

                    arguments = ["py", f'{current_absolute_path}/ressources/xca/xcauto.py', dumps(xca_data)]
                    output = Popen(arguments).wait()

                    if (output != 0):
                        exit()

                source = f'configurations/{chosen_configuration_name}/xca/database/{database_name}'
                destination = f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}/tree/usr/share/CNC_PKI/{database_name}'

                copy_file(source, destination)

        #
        #####################################  R S A  #######################################
        #  

        if "rsa" in data.keys():
            for rsa_key in data["rsa"]:

                key_user = rsa_key["key_user"]
                key_size = rsa_key["key_size"]
                keys_path = f'configurations/{chosen_configuration_name}/rsa/'

                private_key_name = hostname
                private_key_file = Path(keys_path, private_key_name)

                public_key_name = private_key_name + ".pub"
                public_key_file = Path(keys_path, public_key_name)

                recursive_mkdir(keys_path)

                if not private_key_file.is_file():

                    command = ["ssh-keygen", "-t", "rsa", "-m", "PEM", "-P", "", "-b", key_size, "-f", str(private_key_file)]
                    process = Popen(command, stdout=PIPE)
                    process.wait()

                    public_key_file_content = ""

                    with open(public_key_file, "r") as fd:
                        public_key_file_content = fd.read()
                        public_key_file_content = public_key_file_content.split(" ")
                        public_key_file_content = " ".join(public_key_file_content[:2])

                    with open(public_key_file, "w") as fd:
                        fd.write(public_key_file_content)

                if data["os"] == "centos":
                    copy_file(private_key_file, f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}/tree/home/{key_user}/.ssh/id_rsa')
                    copy_file(public_key_file, f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}/tree/home/{key_user}/.ssh/id_rsa.pub')

                elif data["os"] == "windows":
                    copy_file(private_key_file, f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}/tree/Utilisateurs/{key_user}/.ssh/id_rsa')
                    copy_file(public_key_file, f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}/tree/Utilisateurs/{key_user}/.ssh/id_rsa.pub')

    for hostname, data in host_list.items():

        if "domain" in data.keys(): 
            domain = data["domain"]

        print("\n", "#" * 50, hostname, "#" * 50, "\n")

        #
        ####################################  B I O S  ##################################
        #

        if "bios" in data.keys():

            file_name = data["bios"]
            file_path = f'ressources/bios/{file_name}'
            copy_file(file_path)

        #
        #################################  P A C K A G E S  ###############################
        #

        if data["os"] == "centos":

            copy_file("ressources/tree/etc/yum.repos.d/centos-local.repo")
            copy_file("ressources/tree/etc/yum.repos.d/epel-local.repo")

        #
        ####################################  F S T A B  ##################################
        #

        if data["os"] == "centos":

            copy_file("ressources/tree/etc/fstab")

        #
        ###################################  U   M A S K  #################################
        #

        if data["os"] == "centos":

            copy_file("ressources/tree/etc/profile")

        #
        #################################  S Y S T E M   C T L  ###########################
        #

        if data["os"] == "centos":

            copy_file("ressources/tree/etc/sysctl.conf")

        #
        ######################################  P A M  ####################################
        #

        if data["os"] == "centos":

            copy_file("ressources/tree/etc/security/faillock.conf")
            copy_file("ressources/tree/usr/share/authselect/default/sssd/password-auth")
            copy_file("ressources/tree/usr/share/authselect/default/sssd/system-auth")

        #
        #######################################  A D  #####################################
        #

        if data["os"] == "centos":

            if "ad" in data.keys():

                copy_file("ressources/tree/etc/nsswitch.conf")

        #
        #####################################  R O O T  ###################################
        #

        if data["os"] == "centos":

            if "root" in data.keys():
                values = ""

                for group in data["root"]:
                    values += f"%{group}@{domain} ALL=(ALL) ALL\n"

                append_to_file(f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}/tree/etc/sudoers.d/domain_admins', values)

        #
        #####################################  N X L O G  ###################################
        #

        if "nxlog" in data.keys():
            copy_tree("ressources/nxlog")

            CA_certificate = data["nxlog"]["CA_certificate"]
            copy_file(f'configurations/{chosen_configuration_name}/xca/certificates/{CA_certificate}', f'ressources/nxlog/cert/{CA_certificate}')

            source = "ressources/nxlog/conf/nxlog.conf"
            values = {
                "[fqdn]": f'{data["nxlog"]["server"]}.{domain}',
                "[port]": data["nxlog"]["port"],
                "[ca]": CA_certificate
            }

            configure_file(source, values)

        #
        #####################################  S N M P  ###################################
        #

        if "snmp" in data.keys():

            if data["os"] == "windows":
                copy_tree("ressources/net-snmp")

                values = {
                    "[snmp_user]": data["snmp"]["snmp_user"],
                    "[hash_algo]": data["snmp"]["hash_algo"],
                    "[hash_password]": data["snmp"]["hash_password"],
                    "[crypto_algo]": data["snmp"]["crypto_algo"],
                    "[crypto_password]": data["snmp"]["crypto_password"]
                }

                configure_file("ressources/net-snmp/usr/etc/snmp/snmpd.conf", values)

            elif data["os"] == "centos":

                values = {
                    "[snmp_user]": data["snmp"]["snmp_user"],
                    "[hash_algo]": data["snmp"]["hash_algo"],
                    "[hash_password]": data["snmp"]["hash_password"],
                    "[crypto_algo]": data["snmp"]["crypto_algo"],
                    "[crypto_password]": data["snmp"]["crypto_password"]
                }

                configure_file("ressources/tree/etc/snmp/snmptrapd.conf", values)
                copy_file("ressources/tree/var/log/snmptrap/snmptrap.log")
                copy_file("ressources/tree/etc/snmp/snmpd.conf")

        #
        ###################################  V E E A M  #####################################
        #

        if data["os"] == "centos":

            if "veeam" in data.keys():

                copy_file("ressources/tree/etc/yum.repos.d/veeam-local.repo")

        #
        ##################################  Z A B B I X  ####################################
        #

        if data["os"] == "centos":

            if "zabbix" in data.keys():

                copy_file("ressources/tree/etc/yum.repos.d/zabbix-local.repo")

                values = {
                    "[db_name]": data["zabbix"]["db_name"],
                    "[db_user]": data["zabbix"]["db_user"],
                    "[db_password]": data["zabbix"]["db_password"],
                    "[hostname]": hostname
                }

                configure_file("ressources/tree/etc/zabbix/web/zabbix.conf.php", values)

                values = {
                    "[db_name]": data["zabbix"]["db_name"],
                    "[db_user]": data["zabbix"]["db_user"],
                    "[db_password]": data["zabbix"]["db_password"]
                }

                configure_file("ressources/tree/etc/zabbix/zabbix_server.conf", values)

                copy_file("ressources/tree/etc/php-fpm.d/zabbix.conf")
                copy_file("ressources/tree/etc/httpd/conf/httpd.conf")
                copy_file("ressources/tree/etc/httpd/conf.d/ssl.conf")
                copy_file("ressources/tree/usr/bin/zabbix_trap_receiver.pl")

                # ZABBIX WEB APP

                zabbix_configuration = {
                    "zabbix_export": {
                        "version": "5.2",
                        "date": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "groups": [],
                        "hosts": [],
                        "templates": []
                    }
                }

                for hostname2, data2 in host_list.items():
                    host2, domain2 = hostname2.split('.', 1)
                    if domain == domain2:
                        if "snmp" in data2.keys():

                            # TEMPLATES
                            for template in data2["snmp"]["templates"]:

                                template_file = f'ressources/zabbix/templates/{template}.json'

                                if Path(template_file).is_file():
                                    with open(template_file, "r") as fd:
                                        file_content = loads(fd.read())
                                        template = file_content["zabbix_export"]["templates"][0]
                                        template_name_list = [template["name"] for template in zabbix_configuration["zabbix_export"]["templates"]]
                                        if template["name"] not in template_name_list:
                                            zabbix_configuration["zabbix_export"]["templates"].append(template)

                                    if {"name": "Templates"} not in zabbix_configuration["zabbix_export"]["groups"]:
                                        zabbix_configuration["zabbix_export"]["groups"].append({"name": "Templates"})

                            # GROUPS
                            for group in data2["snmp"]["groups"]:
                                if {"name": group} not in zabbix_configuration["zabbix_export"]["groups"]:
                                    zabbix_configuration["zabbix_export"]["groups"].append({"name": group})

                            # DETAILS
                            details = {}

                            if ("version" in data2["snmp"].keys()) and (data2["snmp"]["version"] == "2"):
                                details = {"community": data2["snmp"]["community"]}
                            else:
                                details = {
                                    "version": "SNMPV3",
                                    "securityname": data2["snmp"]["snmp_user"],
                                    "securitylevel": "AUTHPRIV",
                                    "authprotocol": data2["snmp"]["hash_algo"],
                                    "authpassphrase": data2["snmp"]["hash_password"],
                                    "privprotocol": data2["snmp"]["crypto_algo"],
                                    "privpassphrase": data2["snmp"]["crypto_password"]
                                }

                            ### 
                            zabbix_configuration["zabbix_export"]["hosts"].append({
                                "host": hostname2,
                                "name": hostname2,
                                "templates": [{"name": template} for template in data2["snmp"]["templates"]],
                                "groups": [{"name": group} for group in data2["snmp"]["groups"]],
                                "interfaces": [
                                    {
                                        "type": "SNMP",
                                        "useip": "NO",
                                        "dns": hostname2,
                                        "port": "161",
                                        "details": details,
                                        "interface_ref": "if1"

                                    }
                                ],
                                "inventory_mode": "DISABLED",
                            })

                file_path = f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}/zabbix_configuration.json'
                file_content = dumps(zabbix_configuration, indent=4)

                append_to_file(file_path, file_content)

        #
        ##################################  R S Y S L O G   S E R V E R  ####################################
        #

        if data["os"] == "centos":

            if "rsyslog_server" in data.keys():        

                copy_file(f'configurations/{chosen_configuration_name}/xca/certificates/{data["rsyslog_server"]["ca_filename"]}', "ressources/tree/etc/rsyslog-keys/ca.crt")
                copy_file(f'configurations/{chosen_configuration_name}/xca/certificates/{hostname}.crt', "ressources/tree/etc/rsyslog-keys/ssl.crt")
                copy_file(f'configurations/{chosen_configuration_name}/xca/private_keys/{hostname}.key', "ressources/tree/etc/rsyslog-keys/ssl.key")

                copy_file("ressources/tree/etc/rsyslog.d/log-server.conf")

        #
        ##################################  LOG  ####################################
        #

        if data["os"] == "centos":

            if "log" in data.keys(): 

                logfile_configurations = []

                for logfile_configuration in data["log"]:

                    logfile_configurations.append("\n".join(logfile_configuration["logfile_path_list"]) + """
    {
        # Les fichiers journaux font l'objet d'une rotation quotidienne
        daily
        # Seulement les 2 rotations les plus récentes, sont conservées
        rotate 2
        # La rotation du fichier intervient uniquement lorsque la taille du fichier est supérieure à la valeur spécifiée
        size """ + logfile_configuration['logfile_max_size'] + """
        # Si le fichier n'existe pas, ne pas générer de message d'erreur
        missingok
        # Ne pas faire de rotation si le contenu du fichier est vide
        notifempty
        # Les lignes entre postrotate et endscript sont exécutées (en utilisant /bin/sh) après la rotation du fichier journal
        postrotate
        /usr/bin/systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
        endscript
        # Cette option permet aux scripts de ne s'exécuter qu'une seule fois
        sharedscripts 
    }""")

                values = {
                    "[logfile_configurations]": "\n".join(logfile_configurations)
                }

                configure_file("ressources/tree/etc/logrotate.d/syslog", values)

        #
        ##################################  S A M B A  ####################################
        #

        if data["os"] == "centos":

            if "samba_server" in data.keys():

                values = {
                    "[domain]": data["domain"],
                    "[workgroup]": data["domain"].split('.')[0],
                    "[interface]": data["samba_server"]["listening_interface"],
                    "[service_user]": data["samba_server"]["service_user"]
                }

                configure_file("ressources/tree/etc/samba/smb.conf", values)

                values = {
                    "[domain]": data["domain"],
                    "[admin]": data["samba_server"]["admin"]
                }

                configure_file("ressources/tree/etc/samba/user.map", values)      

                copy_file("ressources/tree/etc/nsswitch.conf")

        #
        ######################################  S S H  ####################################
        #

        if data["os"] == "centos":
            if "ssh" in data.keys():

                source = Path("ressources/tree/etc/ssh/sshd_config")

                values = {
                    "[ssh_listening_addresses]": "",
                    "[custom_keying]": "",
                    "[ssh_groups_allowed]": "AllowGroups ",
                    "[ssh_groups]": "",
                    "[max_startups]": "#MaxStartups 10:30:100",
                    "[ssh_match_group]": ""
                }

                if "veeam_stockage" in data.keys():
                    values["[custom_keying]"] = "KexAlgorithms diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha256"

                for interface, details in data["ssh"].items():

                    if "listening_address" in details.keys():

                        values["[ssh_listening_addresses]"] += f'ListenAddress {details["listening_address"]}\n'
                        values["[ssh_groups_allowed]"] += details["allow_groups"] + " "

                        #
                        # EXEMPLE :
                        #
                        #   # ADMIN
                        #   Match LocalAddress 10.97.136.210
                        #       AllowGroups wheel centos_admins@py.dpn.edf.fr
                        #       DenyGroups centos_services@py.dpn.edf.fr
                        #
                        ssh_groups = [""]
                        ssh_groups.append(f'# {interface.upper()}')
                        ssh_groups.append(f'Match LocalAddress {details["listening_address"]}')
                        ssh_groups.append(f'    AllowGroups {details["allow_groups"]}')

                        if "deny_groups" in details.keys():
                            ssh_groups.append(f'    DenyGroups {details["deny_groups"]}')

                        values["[ssh_groups]"] += "\n".join(ssh_groups)

                        if "max_startups" in details.keys():
                            values["[max_startups]"] = f'MaxStartups {details["max_startups"]}'

                        if "match_group" in details.keys():
                            for group, group_values in details["match_group"].items():
                                values["[ssh_match_group]"] += f'\n\nMatch Group {group}\n'

                                for group_value in group_values:
                                    values["[ssh_match_group]"] += f'\t{group_value}\n'

                configure_file(source, values)

        #
        ######################################  N T P  ####################################
        #

        if data["os"] == "centos":

            if "ntp" in data.keys():

                source = Path("ressources/tree/etc/chrony.conf")
                values = {
                    "[chrony_server_address]": data["ntp"]["chrony_server"],
                    "[key_id]": "",
                    "[key_file]": "",
                    "[comment_if_no_key]": "# "
                }

                if "key" in data["ntp"].keys():
                    values["[comment_if_no_key]"] = ""
                    values["[key_id]"] = "key " + data["ntp"]["key"]["id"]

                    file = f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}/tree/etc/chrony.keys'

                    key_id = data["ntp"]["key"]["id"]
                    key_algorithm = data["ntp"]["key"]["algorithm"]
                    key_secret_encode = data["ntp"]["key"]["encode"]
                    key_secret = data["ntp"]["key"]["secret"]
                    key_configuration = f'{key_id} {key_algorithm} {key_secret_encode}:{key_secret}'

                    append_to_file(file, key_configuration)

                configure_file(source, values)

        #
        ##################################  R S Y S L O G  ################################
        #

        if data["os"] == "centos":

            if "rsyslog" in data.keys():

                copy_file("ressources/tree/etc/rsyslog.conf")

                source = Path("ressources/tree/etc/rsyslog.d/log-client.conf")
                values = {
                    "[comment_if_no_tls]": "#",
                    "[rsyslog_server]": data["rsyslog"]["rsyslog_server"],
                    "[rsyslog_port]": data["rsyslog"]["rsyslog_port"],
                    "[rsyslog_protocol]": "@@" if data["rsyslog"]["rsyslog_protocol"] == "tcp" else "@"
                }

                if "ca_filename" in data["rsyslog"].keys():

                    values["[comment_if_no_tls]"] = ""
                    copy_file(f'configurations/{chosen_configuration_name}/xca/certificates/{data["rsyslog"]["ca_filename"]}', "ressources/tree/etc/rsyslog-keys/ca.crt")
                    copy_file(f'configurations/{chosen_configuration_name}/xca/certificates/{hostname}.crt', "ressources/tree/etc/rsyslog-keys/ssl.crt")
                    copy_file(f'configurations/{chosen_configuration_name}/xca/private_keys/{hostname}.key', "ressources/tree/etc/rsyslog-keys/ssl.key")

                configure_file(source, values)

        #
        ##################################  R S Y S L O G  ################################
        #

        if data["os"] == "windows":  

            if "gpo" in data.keys():   

                dest = f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}/gpo/'
                copy_tree(f'ressources/gpo/{data["gpo"]}', dest)

                dest += "migration_table.migtable"
                source = f'ressources/gpo/{data["gpo"]}/migration_table.migtable'

                with open(source, "r", encoding="utf-16") as source_migration_table:

                    dest_content = ""
                    next_line = None

                    for line in source_migration_table:

                        if (next_line != None):

                            dest_content += next_line
                            next_line = None

                        #
                        #   <Source>0KCC620HC-SLP$@DI.DS6.EDF.FR</Source>
                        #
                        elif ("<Source>" in line) and ("@" in line):
                            next_line = line.replace("Source>", "Destination>")

                            domain_start = next_line.index("@") + 1 
                            domain_end = next_line.index("</")

                            next_line = next_line.replace(next_line[domain_start:domain_end], domain)
                            dest_content += line

                        else:
                            dest_content += line

                    with open(dest, 'w', encoding="utf-16") as dest_migration_table:
                        dest_migration_table.write(dest_content)

       #
       ######################## P O W E R S H E L L  ##################################
       #

        if data["os"] == "windows":

            source = Path("ressources/windows.ps1")
            values = {
                "[hostname]": hostname.split(".")[0],
                "[routes]": "",
                "[address_to_ping]": "",
                "[domain]": data["domain"],
                "[snmp_user]": data["snmp"]["snmp_user"],
                "[hash_password]": data["snmp"]["hash_password"],
                "[crypto_password]": data["snmp"]["crypto_password"],
                "[hash_algo]": data["snmp"]["hash_algo"],
                "[crypto_algo]": data["snmp"]["crypto_algo"],
                "[event_log]": "",
                "[has_tree_update]": "$false"
            }

            if "rsa" in data.keys():
                values["[has_rsa_keys]"] = "$true"

            else:
                values["[has_rsa_keys]"] = "$false"

            if "event_log" in data.keys():

                values["[has_event_logs]"] = "$true"

                for event_log, status in data["event_log"].items():
                    values["[event_log]"] += f'$event_log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration "{event_log}"; $event_log.IsEnabled = ${status}; $event_log.SaveChanges()\n'
                    values["[event_log]"] += f'Write-Host "Journal \"{event_log}\" {("activé" if status == "true" else "désactivé")}"\n'

            else:
                values["[has_event_logs]"] = "$false"

            if "vmware_tools" in data.keys():
                values["[has_vmware_tools]"] = "$true"

            else:
                values["[has_vmware_tools]"] = "$false"

            if "certificate" in data.keys():

                values["[certificates]"] = []
                values["[has_certificates]"] = "$true"

                certificates = [
                    {"file_path": f'{data["certificate"]["root"]}.crt', "cert_store_location": "Cert:\\LocalMachine\\AuthRoot"},
                    {"file_path": f'{data["certificate"]["ca"]}.crt', "cert_store_location": "Cert:\\LocalMachine\\CA"},
                    {"file_path": f'{hostname}.crt', "cert_store_location": "Cert:\\LocalMachine\\My"}
                ]

                for certificate in certificates:

                    file_path = certificate["file_path"]
                    cert_store_location = certificate["cert_store_location"]

                    cert_source_path = f'configurations/{chosen_configuration_name}/xca/certificates/{file_path}'
                    cert_dest_path = f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}/certificates/{file_path}'

                    copy_file(cert_source_path, cert_dest_path)
                    values["[certificates]"].append('@{file_path=".\\certificates\\' + file_path + '"; cert_store_location="' + cert_store_location + '"}')

                values["[certificates]"] = ",".join(values["[certificates]"])

            else:
                values["[has_certificates]"] = "$false"

            if "drivers" in data.keys():
                values["[has_drivers]"] = "$true"
                values["[drivers]"] = '@("' + '", "'.join(data["drivers"]) + '")'

            else:
                values["[has_drivers]"] = "$false"

            if "tasks" in data.keys():
                values["[has_tasks]"] = "$true"
                values["[has_tree_update]"] = "$true"
                values["[tasks]"] = []

                for task in data["tasks"]:
                    task['name'] = task['name'].replace("'", " ")
                    task['description'] = task['description'].replace("'", " ")

                    if "event" in task.keys():
                        event = f"'{task['event']}'"
                    else:
                        event = "$null"

                    if "time" in task.keys():
                        time = f"'{task['time']}'"
                    else:
                        time = "$null"

                    values["[tasks]"].append("@{" + f"name = '{task['name']}'; description = '{task['description']}'; execute = '{task['execute']}'; argument = '{task['argument']}'; user = '{task['user']}'; password = '{task['password']}'; event = {event}; time = {time};" + "}")

                    if "files" in task.keys():

                        for file_name, file_details in task["files"].items():

                            destination = file_details["destination"]
                            configuration = {}

                            if "configuration" in file_details.keys():
                                configuration = file_details["configuration"]

                            configure_file(f'ressources/tasks/{file_name}', configuration, f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}/tree/{destination}/{file_name}')

                values["[tasks]"] = f'@({", ".join(values["[tasks]"])})'

            else:
                values["[has_tasks]"] = "$false"

            if "block_usb" in data.keys():
                values["[has_usb_blocking]"] = "$true"
                copy_file("ressources/tasks/eject_unauthorized_usb.ps1", f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}/USB/eject_unauthorized_usb.ps1')

            else:
                values["[has_usb_blocking]"] = "$false"

            if "ad" in data.keys():
                values["[ad_admin]"] = data["ad"]["user"]
                values["[ad_password]"] = data["ad"]["password"]
                values["[path]"] = data["ad"]["path"]

            if "nxlog" in data.keys():
                values["[has_nxlog]"] = "$true"
            else:
                values["[has_nxlog]"] = "$false"

            #
            #####################################  W D A C  ###################################
            #

            if "wdac" in data.keys():

                values["[has_wdac]"] = "$true"
                values["[wdac_profile]"] = data["wdac"]

                copy_tree(f'ressources/wdac/{data["wdac"]}/', f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}/wdac')

                for file in ["audit", "applique"]:
                    copy_file(f'ressources/wdac/{file}.ps1', f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}/wdac/{file}.ps1')

            else:
                values["[has_wdac]"] = "$false"

            #
            #####################################  NTP-WINDOW  ###################################
            #

            if "ntp_window" in data.keys():
                values["[has_ntp_window]"] = "$true"
                values["[ntp_window]"] = data["ntp_window"]
            else:
                values["[has_ntp_window]"] = "$false"

            #
            #####################################  L I C E N C E S  ###################################
            #

            if "licences" in data.keys():
                values["[has_licences]"] = "$true"
                values["[licences]"] = data["licences"]
            else:
                values["[has_licences]"] = "$false"

            #
            #####################################  S N M P  ###################################
            #

            if "snmp" in data.keys():
                values["[has_snmp]"] = "$true"
                values["[snmp_user]"] = data["snmp"]["snmp_user"]
                values["[hash_algo]"] = data["snmp"]["hash_algo"]
                values["[hash_password]"] = data["snmp"]["hash_password"]
                values["[crypto_algo]"] = data["snmp"]["crypto_algo"]
                values["[crypto_password]"] = data["snmp"]["crypto_password"]

            else:
                values["[has_snmp]"] = "$false"

            if "gpo" in data.keys():

                values["[has_gpo]"] = "$true"

            else:
                values["[has_gpo]"] = "$false"

            if "ad_server" in data.keys():

                values["[install_ad]"] = "$true"
                values["[netbios_name]"] = hostname.split('.')[1]
                values["[ad_server_login]"] = data["ad_server"]["credentials"]["login"]
                values["[ad_server_password]"] = data["ad_server"]["credentials"]["password"]

                #
                #   DNS
                #

                values["[dns_entries]"] = []

                for hostname2, data2 in host_list.items():
                    host2, domain2 = hostname2.split('.', 1)

                    if domain == domain2:
                        if "network" in data2.keys():
                            for interface, details in data2["network"].items():
                                if "dns_name" in details.keys():

                                    name = details["dns_name"].split(".")[0]
                                    ip = details["interface"]["address"]

                                    values["[dns_entries]"].append('@{name = "' + name + '"; ip = "' + ip + '"}')

                values["[dns_entries]"] = ",".join(values["[dns_entries]"])

                units = []
                users = []
                groups = []
                members = []
                computers = []

                #
                #   GROUPS
                #

                for group in data["ad_server"]["groups"]:

                    name = group["name"]

                    #
                    # "OU=Zabbix,OU=Services,DC=DI,DC=DS3,DC=EDF,DC=FR"
                    #
                    path = group["path"]

                    #
                    # 1. "OU=Zabbix,OU=Services,DC=DI,DC=DS3,DC=EDF,DC=FR"
                    # 2. ["OU=Zabbix", "OU=Services", "DC=DI", "DC=DS3", "DC=EDF", "DC=FR"]
                    #
                    path_splited = path.split(",")

                    DC = [path_part for path_part in path_splited if "OU=" not in path_part]
                    #
                    # 1. ["DC=DI", "DC=DS3", "DC=EDF", "DC=FR"]
                    #
                    DC_temp = DC

                    if "CN=" not in path:

                        #
                        # 1. ["OU=Zabbix", "OU=Services", "DC=DI", "DC=DS3", "DC=EDF", "DC=FR"]
                        # 2. ["OU=Services", "OU=Zabbix"]
                        #
                        for path_part in reversed(path_splited):

                            if "DC=" in path_part:
                                continue

                            #
                            # 1. "OU=Services"
                            # 2. "Services"
                            #
                            unit_name = path_part.replace("OU=", "")
                            unit_path = ",".join(DC_temp)
                            command = f'New-ADOrganizationalUnit "{unit_name}" -Path "{unit_path}"'

                            if command not in units:
                                units.append(f'Write-Host "Organization unit {unit_name} created."')
                                units.append(command)

                            #
                            # 1. ["DC=DI", "DC=DS3", "DC=EDF", "DC=FR"]
                            # 2. ["OU=Services", "DC=DI", "DC=DS3", "DC=EDF", "DC=FR"]
                            #
                            DC_temp.insert(0, path_part)

                        groups.append(f'Write-Host "Group {name} created."')
                        groups.append(f'New-ADGroup "{name}" -Path "{path}" -GroupScope "Global"')

                    if "members" in group.keys():
                        for member in group["members"]:

                            name = group["name"]
                            path = ",".join(DC)
                            member_name = member["name"]

                            members.append("Write-Host 'User \"" + member_name + "\" added to the group \"" + name + "\".'")
                            members.append(f'Add-ADGroupMember -Identity "CN={name},{path}" -Members "{member_name}"')

                #
                #   COMPUTER
                #

                computer_path_list = []

                for hostname2, data2 in host_list.items():
                    host2, domain2 = hostname2.split('.', 1)

                    if domain == domain2:
                        if "ad" in data2.keys():
                            if "path" in data2["ad"].keys():

                                paths = data2["ad"]["path"]
                                name = host2
                                dns_hostname = hostname2

                                if paths not in computer_path_list:
                                    computer_path_list.append(paths)

                                computers.append(f'  New-ADComputer -Name "{name}" -DNSHostName "{dns_hostname}" -Path "{paths}"\n')

                for computer_path in computer_path_list:

                    #
                    # 1. "OU=Zabbix,OU=Services,DC=DI,DC=DS3,DC=EDF,DC=FR"
                    # 2. ["OU=Zabbix", "OU=Services", "DC=DI", "DC=DS3", "DC=EDF", "DC=FR"]
                    #
                    path_splited = computer_path.split(",")

                    CN = [path_part for path_part in path_splited if "OU=" not in path_part]
                    DC_temp = CN

                    if "CN=" not in computer_path:

                        #
                        # 1. ["OU=Zabbix", "OU=Services", "DC=DI", "DC=DS3", "DC=EDF", "DC=FR"]
                        # 2. ["OU=Services", "OU=Zabbix"]
                        #
                        for path_part in reversed(path_splited):

                            if "DC=" in path_part:
                                continue

                            #
                            # 1. "OU=Services"
                            # 2. "Services"
                            #
                            unit_name = path_part.replace("OU=", "")
                            unit_path = ",".join(DC_temp)
                            command = f'New-ADOrganizationalUnit "{unit_name}" -Path "{unit_path}"'

                            if command not in units:
                                units.append(f'Write-Host "Organization unit {unit_name} created."')
                                units.append(command)

                            #
                            # 1. ["DC=DI", "DC=DS3", "DC=EDF", "DC=FR"]
                            # 2. ["OU=Services", "DC=DI", "DC=DS3", "DC=EDF", "DC=FR"]
                            #
                            DC_temp.insert(0, path_part)
                #
                #   USERS
                #

                for user in data["ad_server"]["users"]:

                    #
                    # "OU=Zabbix,OU=Services,DC=DI,DC=DS3,DC=EDF,DC=FR"
                    #
                    path = user["path"]

                    #
                    # 1. "OU=Zabbix,OU=Services,DC=DI,DC=DS3,DC=EDF,DC=FR"
                    # 2. ["OU=Zabbix", "OU=Services", "DC=DI", "DC=DS3", "DC=EDF", "DC=FR"]
                    #
                    path_splited = path.split(",")

                    CN = [path_part for path_part in path_splited if "OU=" not in path_part]
                    DC_temp = CN

                    if "CN=" not in path:

                        #
                        # 1. ["OU=Zabbix", "OU=Services", "DC=DI", "DC=DS3", "DC=EDF", "DC=FR"]
                        # 2. ["OU=Services", "OU=Zabbix"]
                        #
                        for path_part in reversed(path_splited):

                            if "DC=" in path_part:
                                continue

                            #
                            # 1. "OU=Services"
                            # 2. "Services"
                            #
                            unit_name = path_part.replace("OU=", "")
                            unit_path = ",".join(DC_temp)
                            command = f'New-ADOrganizationalUnit "{unit_name}" -Path "{unit_path}"'

                            if command not in units:
                                units.append(f'Write-Host "Organization unit {unit_name} created2."')
                                units.append(command)

                            #
                            # 1. ["DC=DI", "DC=DS3", "DC=EDF", "DC=FR"]
                            # 2. ["OU=Services", "DC=DI", "DC=DS3", "DC=EDF", "DC=FR"]
                            #
                            DC_temp.insert(0, path_part)

                    name = user["name"]
                    password = user["password"]
                    path = user["path"]
                    password_never_expires = "false"

                    if ("password_never_expires" in user.keys()) and (user["password_never_expires"]):
                        password_never_expires = "true"

                    users.append("Write-Host 'User \"" + name + "\" created.'")
                    users.append(f"New-ADUser -Enabled:$true -ChangePasswordAtLogon:$false -Name '{name}' -AccountPassword (ConvertTo-SecureString -AsPlainText -Force '{password}') -Path '{path}' -PasswordNeverExpires ${password_never_expires}")

                gpo_list = []

                for gpo in data["ad_server"]["gpo"]:

                    name = gpo["name"]
                    target = gpo["target"]
                    permissions = ""

                    if ("permissions" in gpo.keys()):
                        permissions = '","'.join(gpo["permissions"])

                    gpo_list.append('@{name="' + name + '"; target="' + target + '"; permissions=@("' + permissions + '")}')

                gpo_list = ",\n\t\t".join(gpo_list)
                values["[gpo_list]"] = "@(\n\t\t" + gpo_list + "\n\t)"

                #
                #
                #

                # for hostname2, data2 in host_list.items():
                #    host2, domain2 = hostname2.split('.', 1)

                #    if (domain == domain2) and ("ad" in data2.keys()):

                #        DC = ",".join([path_part for path_part in data2["ad"]["path"].split(",") if "DC=" in path_part])

                #        identity = f'CN={host2},CN=Computers,{DC}'
                #        target_path = data2["ad"]["path"]

                #        computers.append(f'Move-ADObject -Identity "{identity}" -TargetPath "{target_path}"')
                #        computers.append(f'Write-Host "Ordinateur {hostname2} déplacé vers {target_path}"')

                #
                #
                #
                values["[units]"] = "\n".join(units)
                values["[users]"] = "\n".join(users)
                values["[groups]"] = "\n".join(groups)
                values["[members]"] = "\n".join(members)
                values["[computers]"] = "\n".join(computers)

            else:

                values["[install_ad]"] = "$false"

            # if "tasks" in data.keys():
            #    values["[tasks]"] = "$true"
            #    values["[short_domain]"] = data["tasks"]["short_domain"]
            #    values["[service_account]"] = data["tasks"]["service_account"]

            #    copy_file("ressources/tasks/Lancement_Panorama_Sur_Mur_Ecran.ps1")

            # else:
            #    values["[tasks]"] = "$false"

            if "network" in data.keys():

                values["[has_ip]"] = "$true"
                values["[network]"] = []
                values["[routes]"] = []
                values["[address_to_ping]"] = []
                values["[dns]"] = []

                for card_name, card_data in data["network"].items():

                    if "enabled" in card_data.keys() and card_data["enabled"] == "false":
                        continue

                    values["[network]"].append('$steps += @{' + f'question = "Configurer l\'interface réseau {card_name} ?"; action = \'setup_network_interface -current_interface_name "{card_data["interface"]["name"]}" -new_interface_name "{card_name}" -interface_ipv4_address "{card_data["interface"]["address"]}" -subnetwork_mask "{card_data["interface"]["mask"]}"\'' + '}')

                    if "routes" in card_data.keys():
                        for route in card_data["routes"]:
                            values["[routes_question]"] = '$steps += @{question = "Configurer les routes statiques ?"; action = "setup_static_routes"}'
                            values["[routes]"].append(f'route add -p {route[0]} mask {route[1]} {route[2]}')
                            values["[address_to_ping]"].append(f'"{route[0]}"')

                    if "dns" in card_data["interface"].keys():
                        values["[dns]"].append('$steps += @{' + f'question = "Configurer les DNS (Domain Name Service) pour la carte {card_name} ?"; action = \'setup_dns_client -interface_name "{card_name}" -dns "{card_data["interface"]["dns"][0]}"\'' + '}')

                values["[network]"] = "\n".join(values["[network]"])

                if len(values["[address_to_ping]"]) > 1:
                    values["[address_to_ping]"] = ", ".join(values["[address_to_ping]"])
                elif len(values["[address_to_ping]"]) == 1:
                    values["[address_to_ping]"] = values["[address_to_ping]"][0]
                else:
                    values["[address_to_ping]"] = ""

                if len(values["[routes]"]) > 1:
                    values["[has_routes]"] = "$true"
                    values["[routes]"] = "\n".join(values["[routes]"])
                elif len(values["[routes]"]) == 1:
                    values["[has_routes]"] = "$true"
                    values["[routes]"] = values["[routes]"][0]
                else:
                    values["[routes]"] = ""
                    values["[has_routes]"] = "$false"

                if len(values["[dns]"]) > 1:
                    values["[has_dns]"] = "$true"
                    values["[dns]"] = "\n".join(values["[dns]"])
                elif len(values["[dns]"]) == 1:
                    values["[has_dns]"] = "$true"
                    values["[dns]"] = values["[dns]"][0]
                else:
                    values["[dns]"] = ""
                    values["[has_dns]"] = "$false"

            else:
                values["[has_ip]"] = "$false"
                values["[has_routes]"] = "$false"
                values["[has_dns]"] = "$false"

            configure_file(source, values)

        #
        ######################## P O W E R S H E L L - Hyperviseur ##################################
        #

        if data["os"] == "VMware_ESXI":

            source = Path(f'ressources/esxi.ps1')

            # Définir les valeures sources constantes.
            values = {
                "[esxi_domain]": data["domain"],
                "[esxi_ip]": data["ip"],
                "[esxi_hostname]": hostname.split(".")[0],
                "[esxi_fqdn]": hostname,
                "[esx_portgroups]": "",
                "[esx_vswitchs]": "",
                "[esx_vms]": "",
                "[esx_mac]": "",
                "[esx_licence_key]": data["esx_licence_key"],
                "[server_certificate]": hostname + ".crt",
                "[server_private_key]": hostname + ".key"
            }

            copy_file(f'configurations/{chosen_configuration_name}/xca/certificates/{hostname}.crt', f'ressources/certificates/{hostname}.crt')
            copy_file(f'configurations/{chosen_configuration_name}/xca/private_keys/{hostname}.key', f'ressources/private_keys/{hostname}.key')

            if "esx_certificat_ca" in data.keys():

                ca = data["esx_certificat_ca"]
                copy_file(f'configurations/{chosen_configuration_name}/xca/certificates/{ca}', f'ressources/certificates/{ca}')

            # Traiter les données de chaque bloc JSON.
            if "esx_identifiants" in data.keys():

                values["[esx_admin_id]"] = data["esx_identifiants"]["esx_admin_id"]
                values["[esx_admin_mdp]"] = data["esx_identifiants"]["esx_admin_mdp"]

            if "esx_hostname" in data.keys():

                values["[esx_hostname_fqdn]"] = data["esx_hostname"]["esx_hostname_fqdn"]

            if "esx_jonction_domaine" in data.keys():

                values["[esx_jonction_domaine_user]"] = data["esx_jonction_domaine"]["esx_jonction_domaine_user"]
                values["[esx_jonction_domaine_password]"] = data["esx_jonction_domaine"]["esx_jonction_domaine_password"]

            if "root" in data.keys():            

                short_domain = data["domain"].split('.')[0]
                values["[admin_group_list]"] = ",".join([f'"{short_domain}\\{group}"' for group in data["root"]])

            if "esx_network" in data.keys():

                values["[esx_network_ntp]"] = data["esx_network"]["esx_network_ntp"]  

            if "esx_services_desactives" in data.keys():

                values["[esx_services_desactives]"] = '"' + '", "'.join(data["esx_services_desactives"]) + '"'

            if "esx_service_syslog" in data.keys():

                copy_file("ressources/vmware/custom-service.xml", f"configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}/custom-service.xml")
                copy_file(f'configurations/{chosen_configuration_name}/xca/certificates/{data["certificate"]["ca"]}.crt', f'ressources/certificates/{data["certificate"]["ca"]}.crt')
                copy_file(f'configurations/{chosen_configuration_name}/xca/certificates/{data["certificate"]["root"]}.crt', f'ressources/certificates/{data["certificate"]["root"]}.crt')

                values["[ca_certificate]"] = f'{data["certificate"]["ca"]}.crt'
                values["[root_certificate]"] = f'{data["certificate"]["root"]}.crt'
                values["[esx_service_syslog_serveur]"] = data["esx_service_syslog"]["esx_service_syslog_serveur"]
                values["[esx_service_syslog_port]"] = data["esx_service_syslog"]["esx_service_syslog_port"]

            if "esx_service_snmp" in data.keys():

                values["[esx_service_snmp_communaute]"] = data["esx_service_snmp"]["esx_service_snmp_communaute"]
                values["[esx_service_snmp_hash_auth]"] = data["esx_service_snmp"]["esx_service_snmp_hash_auth"]
                values["[esx_service_snmp_hash_priv]"] = data["esx_service_snmp"]["esx_service_snmp_hash_priv"]
                values["[esx_service_snmp_hash_auth_algo]"] = data["esx_service_snmp"]["esx_service_snmp_hash_auth_algo"]
                values["[esx_service_snmp_hash_priv_algo]"] = data["esx_service_snmp"]["esx_service_snmp_hash_priv_algo"]
                values["[esx_service_snmp_emplacement_hash]"] = data["esx_service_snmp"]["esx_service_snmp_emplacement_hash"]
                values["[esx_service_snmp_utilisateur_snmp]"] = data["esx_service_snmp"]["esx_service_snmp_utilisateur_snmp"]
                values["[esx_service_snmp_port]"] = data["esx_service_snmp"]["esx_service_snmp_port"]
                values["[esx_service_snmp_cible_SNMP]"] = data["esx_service_snmp"]["esx_service_snmp_cible_SNMP"]

            if "esx_expiration_sessions" in data.keys():

                values["[esx_expiration_sessions_dcui]"] = data["esx_expiration_sessions"]["esx_expiration_sessions_dcui"]
                values["[esx_expiration_sessions_shell]"] = data["esx_expiration_sessions"]["esx_expiration_sessions_shell"]
                values["[esx_expiration_sessions_web]"] = data["esx_expiration_sessions"]["esx_expiration_sessions_web"]

            if "esx_vswitch" in data.keys():

                for group in data["esx_vswitch"]:

                    values["[esx_vswitchs]"] += f'New-VirtualSwitch -VMHost $global:VMware_Esxi -Name {group["vswitch_name"]} -NumPorts {group["vswitch_nbports"]} -nic {group["vswitch_nic"]} -mtu {group["vswitch_mtu"]}\n    '

            if "esx_portgroup" in data.keys():

                for group in data["esx_portgroup"]:

                    values["[esx_portgroups]"] += f'Get-VMHost $global:VMware_Esxi | Get-VirtualSwitch -name {group["esx_portgroup_vswitch"]} | New-VirtualPortGroup -Name {group["esx_portgroup_name"]} -VLanID {group["esx_portgroup_vlan_id"]}\n    '

            if "esx_datastore" in data.keys():

                values["[esx_datastore_old_name]"] = data["esx_datastore"]["esx_datastore_old_name"]
                values["[esx_datastore_new_name]"] = data["esx_datastore"]["esx_datastore_new_name"]

            if "esx_vm" in data.keys():

                iso_list = []
                values["[esx_mac]"] = ""
                values["[esx_iso]"] = ""

                for group in data["esx_vm"]:

                    if group["esx_vm_iso"] not in iso_list:
                        iso_list.append(group["esx_vm_iso"])

                    esx_networks = ", ".join([f'"{vm_network}"' for vm_network in group["esx_vm_network"]])

                    values["[esx_vms]"] += f'$vm = New-VM -Name {group["esx_vm_name"]} -NumCPU {group["esx_vm_cpu"]} -MemoryGB {group["esx_vm_ram"]} -DiskGB {group["esx_vm_disk"]} -Datastore {group["esx_vm_datastore"]} -DiskStorageFormat {group["esx_vm_disk_format"]} -NetworkName {esx_networks} -GuestID {group["esx_vm_GuestID"]}\n    '
                    values["[esx_vms]"] += f'New-CDDrive -VM $vm -ISOPath "[{data["esx_datastore"]["esx_datastore_new_name"]}]/{group["esx_vm_iso"]}" -StartConnected\n    '
                    values["[esx_vms]"] += f'Get-VMStartPolicy -VM $vm | Set-VMStartpolicy -StartAction PowerOn -InheritStartDelayFromHost -InheritStopActionFromHost -InheritStopDelayFromHost -UnspecifiedStartOrder -InheritWaitForHeartbeatFromHost\n    '

                    for mac in group["esx_vm_mac"]:
                        values["[esx_mac]"] += f'Get-VM "{group["esx_vm_name"]}" | Get-NetworkAdapter -Name "{mac["name"]}" | Set-NetworkAdapter -MacAddress "{mac["mac"]}"\n    '

                    # values["[esx_vms]"] += 'Start-VM -VM $vm -RunAsync\n\n    '

                for iso in iso_list:
                    values["[esx_iso]"] += 'Copy-DatastoreItem -Item ((Resolve-Path ".").ToString().Substring(0,2) + "\\ISO\\' + iso + '") -Destination iso:"\\" -Verbose\n    '

            configure_file(source, values)

        #
        ######################## P O W E R S H E L L - Veeam Replication & Backup Server ##################################
        #

        if "veeam_serveur" in data.keys():

            # Sauvegardes sans repository à gérer...

            if "repositories" in data["veeam_serveur"]:

                copy_file(f'ressources/licences/{data["veeam_serveur"]["licence"]}')

                # Indiquer l'emplacement du fichier de template source.
                source = Path("ressources/veeam/veeam.ps1")

                # Définir les valeures sources constantes.
                values = {
                    "[hostname]": hostname.split(".")[0],
                    "[domain]": data["domain"],
                    "[credentials_data]": "",
                    "[srv_backup_data]": "",
                    "[cc_data]": "",
                    "[gp_data]": "", 
                    "[jobs_data]": "",             
                }
                # Traiter les données de chaque bloc JSON.
                # 

                # Compte de service
                values["[compte_service_login]"] = data["veeam_serveur"]["compte_service_login"]
                values["[compte_service_password]"] = data["veeam_serveur"]["compte_service_password"]

                # Boucle de traitement des données du dictionnaire de credentials.
                values["[credentials_data]"] += "@(\n\t\t" + ",\n\t\t".join(["@{" + f'id = \"{credential["id"]}\"; type = \"{credential["type"]}\"; login = \"{credential["login"]}\" ; password = \"{credential["password"]}\"' + "}" for credential in data["veeam_serveur"]["credentials"]]) + "\n\t)"

                # Boucle de traitement des données du dictionnaire de serveur de stockage.
                values["[srv_backup_data]"] += "@(\n\t\t" + ",\n\t\t".join(["@{" + f'id = \"{backup["id"]}\"; type_serveur = \"{backup["type_serveur"]}\"; type_backup = \"{backup["type_backup"]}\" ; hostname = \"{backup["hostname"]}\" ; credentials = \"{backup["credentials"]}\" ; path = \"{backup["path"]}\"' + "}" for backup in data["veeam_serveur"]["repositories"]]) + "\n\t)"

                # Boucle de traitement des données du dictionnaire des custom credentials / containers.
                values["[cc_data]"] += "@(\n\t\t" + ",\n\t\t".join(["@{" + f'id = \"{cc["id"]}\"; type = \"{cc["type"]}\"; hostname = \"{cc["hostname"]}\" ; credentials = \"{cc["credentials"]}\"' + "}" for cc in data["veeam_serveur"]["hosts"]]) + "\n\t)"

                # Boucle de traitement des données du dictionnaire des groupes de protections.
                values["[gp_data]"] += "@(\n\t\t" + ",\n\t\t".join(["@{" + f'id = \"{gp["id"]}\"; containers = @("' + "\", \"".join(gp["containers"]) + '\")' + "}" for gp in data["veeam_serveur"]["protection_groups"]]) + "\n\t)"

                # Boucle de traitement des données du dictionnaire des jobs.
                values["[jobs_data]"] += "@(\n\t\t" + ",\n\t\t".join(["@{" + f'name = \"{job["name"]}\"; frequence = \"{job["frequence"]}\"; options_frequence = \"{job["options_frequence"]}\" ; time = \"{job["time"]}\" ; plateform = \"{job["plateform"]}\" ; type = \"{job["type"]}\" ; backup_repository = \"{job["backup_repository"]}\" ; protection_groups = @("' + "\", \"".join(job["protection_groups"]) + '\")' + "}"for job in data["veeam_serveur"]["jobs"]]) + "\n\t)"

                configure_file(source, values)
        #
        ######################################  N F S  ####################################
        #

        if "nfs" in data.keys():

            source = Path("ressources/tree/etc/exports")
            values = {
                "[mount_points_config]": []
            }

            for nfs in data["nfs"]:
                values["[mount_points_config]"] += [f'{nfs["mount"]} {nfs["ip"]}(rw,all_squash,anonuid={nfs["id"]},anongid={nfs["id"]},sync,no_subtree_check)']

            values["[mount_points_config]"] = "\n".join(values["[mount_points_config]"])

            configure_file(source, values)

        #
        ####################################  S H E L L  ##################################
        #

        if data["os"] == "centos":

            source = Path("ressources/centos.sh")
            values = {
                "[hostname]": hostname,
                "[has_partitioning]": "false",
                "[partitions]": "",
                "[has_services]": "false",
                "[service_list_to_enable]": [],
                "[has_services_to_remove]": "false",
                "[service_list_to_remove_from_firewall]": ["ssh"],
                "[has_services_to_add]": "false",
                "[service_list_to_add_to_firewall]": [],
                "[rich_rules]": [],
                "[has_packages]": "false",
                "[has_packet_groups]": "false",
                "[group_list_to_install]": [],
                "[package_list_to_install]": [],
                "[has_ports_to_open]": "false",
                "[port_list_to_add_to_firewall]": [],
                "[interface_list_to_add_to_firewall]": [],
                "[ping_static_routes]": [],
                "[restart_network_interfaces]": [],
                "[has_modules]": "false",
                "[skel]": "",
                "[has_vmrc]": "false",
                "[has_ssh_keys]": "false",
                "[ssh_keys]": ""
            }

        ########

            if "services" in data.keys():

                if "disable" in data["services"].keys():
                    values["[service_list_to_disable]"] = " ".join(data["services"]["disable"])

        ########

            if "rsa" in data.keys():
                values["[has_ssh_keys]"] = "true"

                for keys in data["rsa"]:
                    values["[ssh_keys]"] += f'chown -R {keys["key_user"]}:{keys["key_user"]} /home/{keys["key_user"]}/.ssh\n'   
                    values["[ssh_keys]"] += f'chmod 0700 /home/{keys["key_user"]}/.ssh\n'
                    values["[ssh_keys]"] += f'chmod 0600 /home/{keys["key_user"]}/.ssh/*\n'

        ########

            if "ssh" in data.keys():
                for interface in data["ssh"].values():
                    if "clients" in interface.keys():
                        for client in interface["clients"]:
                            values["[rich_rules]"] += [f'firewall-cmd --permanent --zone=public --add-rich-rule=\'rule family="ipv4" source address="{client}" port port="22" protocol="tcp" accept\'']

                    if "trusted-keys" in interface.keys():
                        values["[has_ssh_keys]"] = "true"

                        for host, keys in interface["trusted-keys"].items():
                            values["[ssh_keys]"] += f'chown -R {host}:{host} /home/{host}/.ssh\n'
                            values["[ssh_keys]"] += f'chmod 0700 /home/{host}/.ssh\n'
                            values["[ssh_keys]"] += f'chmod 0600 /home/{host}/.ssh/authorized_keys\n'

                            for key in keys:
                                key_file = f'configurations/{chosen_configuration_name}/rsa/{key}.pub'

                                with open(key_file, "r") as fd:
                                    key_content = fd.read() + f' {key}\n\n'
                                    append_to_file(f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}/tree/home/{host}/.ssh/authorized_keys', key_content)

        ########

            if "vmrc" in data.keys():

                copy_file("ressources/vmware/VMware-Remote-Console-12.0.0-17287072.x86_64.bundle")
                values["[has_vmrc]"] = 'true'

        ########

            if "cron" in data.keys():

                for task_details in data["cron"]:

                    user = task_details["user"]
                    cron_file = f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}/tree/var/spool/cron/{user}'

                    minute = task_details["minute"]
                    day = task_details["day"]
                    day_of_month = task_details["day_of_month"]
                    month = task_details["month"]
                    day_of_week = task_details["day_of_week"]
                    task = task_details["task"]

                    value = f'{minute} {day} {day_of_month} {month} {day_of_week}   {task}\n'

                    append_to_file(cron_file, value)

                    line = f'chown {user}:{user} /var/spool/cron/{user}'

                    if "[cron_files]" not in values.keys():
                        values["[cron_files]"] = []

                    if line not in values["[cron_files]"]:
                        values["[cron_files]"].append(f'chown {user}:{user} /var/spool/cron/{user}')

                values["[cron_files]"] = "\n".join(values["[cron_files]"])

        ########

            if "scp_backups" in data.keys():

                values["[has_scp_backup]"] = "true"

                for backup_details in data["scp_backups"]:

                    file = backup_details["file"]
                    folder = "/".join(file.split("/")[:-1])
                    password = backup_details["password"]
                    local_user = backup_details["local_user"]
                    local_group = backup_details["local_group"]
                    backup_user = backup_details["backup_user"]
                    backup_server = backup_details["backup_server"]
                    backup_path = backup_details["backup_path"]

                    if "[scp_backups]" not in values.keys():
                        values["[scp_backups]"] = []

                    values["[scp_backups]"].append(f'chown -R {local_user}:{local_group} {folder}')
                    values["[scp_backups]"].append(f'chmod 770 {folder}/task')

                    append_to_file(f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}/tree{folder}/backupPassPhrase', password)
                    append_to_file(f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}/tree{folder}/last_hash', "")

                    task_file = f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}/tree/{folder}/task'
                    task = f"""#!/usr/bin/env bash

    folder="{folder}"
    file="{file}"
    file_hash=`cat $file | md5sum`

    hash_file="$folder/last_hash"
    last_hash=`cat $hash_file`

    password_file="$folder/backupPassPhrase"
    encrypted_file="$file.crypt"

    backup_user="{backup_user}"
    backup_server="{backup_server}"
    backup_path="{backup_path}"

    if [[ $file_hash != $last_hash ]]
    then 
        echo "$last_hash" > $hash_file
        openssl enc -in $file -out $encrypted_file -aes-256-cbc -pass file:$password_file
        scp $encrypted_file $backup_user@$backup_server:$backup_path
    fi"""
                    append_to_file(task_file, task)

                values["[scp_backups]"] = "\n".join(values["[scp_backups]"])

            else:
                values["[has_scp_backup]"] = "false"

        ########

            if "scp_backups_server" in data.keys():

                values["[is_scp_backup_server]"] = "true"

                for backup_details in data["scp_backups_server"]:

                    if "[scp_folders]" not in values.keys():
                        values["[scp_folders]"] = []

                    user = backup_details["owner_user"] 
                    group = backup_details["owner_group"] 
                    folder = backup_details["backup_folder"]

                    values["[scp_folders]"].append(f'mkdir -p {folder}')
                    values["[scp_folders]"].append(f'chown -R {user}:{group} {folder}')

                values["[scp_folders]"] = "\n".join(values["[scp_folders]"])

            else:
                values["[is_scp_backup_server]"] = "false"

        ########

            if "partitions" in data.keys():

                values["[has_partitioning]"] = "true"

                for partition in data["partitions"]:
                    values["[partitions]"] += f'lvextend -r -L{partition["size"]} {partition["path"]}\n\t'

        ########

            if "modules" in data.keys():

                values["[has_modules]"] = "true"

                for module in data["modules"]:
                    copy_file(f'ressources/tree/etc/selinux/modules/{module}')

        ########

            if "services" in data.keys():

                if "enable" in data["services"].keys():
                    values["[service_list_to_enable]"] += data["services"]["enable"]

        ########

            if "groups" in data.keys():

                values["[has_groups]"] = "true"
                values["[add_groups]"] = ""

                for group in data["groups"]:
                    values["[add_groups]"] += f'groupadd {group}\n'

            else:
                values["[has_groups]"] = "false"

        ########

            if "users" in data.keys():

                values["[has_users]"] = "true"
                values["[add_users]"] = ""

                for user in data["users"]:

                    command = f'adduser {user["name"]} --shell {user["shell"]} '

                    if "group" in user.keys():
                        command += f'--gid {user["group"]}'

                    values["[add_users]"] += f'{command}\n'

            else:
                values["[has_users]"] = "false"

        ########

            if "has_a_gui" in data.keys():

                values["[has_a_gui]"] = "true"
                values["[has_packet_groups]"] = "true"
                values["[group_list_to_install]"] += [data["has_a_gui"]["name"]]

                if "config_sdp" in data["has_a_gui"].keys():

                    values["[skel]"] = '''  subtitle "APPLICATION DE LA CONFIGURATION À L'UTILISATEUR COURANT"
        rm -rfv /home/adminsys/.config/xfce4/panel
        rm -fv /home/adminsys/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-panel.xml
        rm -fv /home/adminsys/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-screensaver.xml
        rm -fv /home/adminsys/.config/xfce4/helpers.rc

        cp -ruv /etc/skel/.config /home/adminsys/
        chown -R adminsys:adminsys /home/adminsys/'''

                    copy_file("ressources/tree/etc/nginx/nginx.conf")
                    copy_tree("ressources/tree/etc/skel")

            else:
                values["[has_a_gui]"] = "false"

        ########

            if "xca" in data.keys():

                values["[has_xca]"] = "true"
                values["[has_packages]"] = "true"
                values["[service_list_to_enable]"] += ["crond"]
                values["[has_packet_groups]"] = "true"
                values["[group_list_to_install]"] += ["\"Development Tools\""]
                values["[package_list_to_install]"] += ["openssl", "openssl-devel", "libtool-ltdl-devel", "qt*"]

            else:
                values["[has_xca]"] = "false"

        ########

            if "yum" in data.keys():

                values["[has_packages]"] = "true"
                values["[package_list_to_install]"] += data["yum"]["packages"]

            else:
                values["[has_a_gui]"] = "false"

        ########

            if "nfs" in data.keys():

                values["[has_nfs]"] = "true"
                values["[has_packages]"] = "true"
                values["[package_list_to_install]"] += ["nfs-utils"]
                values["[service_list_to_enable]"] += ["nfs-server"]
                values["[nfs_mount_point_name]"] = []
                values["[nfs_mount_point_owner]"] = []
                values["[nfs_mount_point_rights]"] = []

                for nfs in data["nfs"]:
                    values["[nfs_mount_point_name]"] += [f'mkdir {nfs["mount"]}']
                    values["[nfs_mount_point_owner]"] += [f'chown {nfs["name"]}:{nfs["name"]} {nfs["mount"]}']
                    values["[nfs_mount_point_rights]"] += [f'chmod 777 {nfs["mount"]}']
                    values["[rich_rules]"] += [f'firewall-cmd --permanent --zone=public --add-rich-rule=\'rule family="ipv4" source address="{nfs["ip"]}" port port="111" protocol="tcp" accept\'']
                    values["[rich_rules]"] += [f'firewall-cmd --permanent --zone=public --add-rich-rule=\'rule family="ipv4" source address="{nfs["ip"]}" port port="2049" protocol="tcp" accept\'']
                    values["[rich_rules]"] += [f'firewall-cmd --permanent --zone=public --add-rich-rule=\'rule family="ipv4" source address="{nfs["ip"]}" port port="20048" protocol="tcp" accept\'']

                values["[nfs_mount_point_name]"] = "\n".join(values["[nfs_mount_point_name]"])
                values["[nfs_mount_point_owner]"] = "\n".join(values["[nfs_mount_point_owner]"])
                values["[nfs_mount_point_rights]"] = "\n".join(values["[nfs_mount_point_rights]"])

            else:
                values["[has_nfs]"] = "false"

        ########

            if "veeam" in data.keys():

                values["[has_packages]"] = "true"
                values["[package_list_to_install]"] += ["veeam"]

                values["[rich_rules]"] += [f'firewall-cmd --permanent --zone=public --add-rich-rule=\'rule family="ipv4" source address="{data["veeam"]["veeam_ip"]}" port port="22" protocol="tcp" accept\'']
                values["[rich_rules]"] += [f'firewall-cmd --permanent --zone=public --add-rich-rule=\'rule family="ipv4" source address="{data["veeam"]["veeam_ip"]}" port port="6162" protocol="tcp" accept\'']

                copy_file("ressources/tree/etc/selinux/modules/veeam_agent_custom_policy.pp")
                copy_file("ressources/tree/etc/selinux/modules/veeam_transport_custom_policy.pp")

            if "veeam_stockage" in data.keys():

                copy_file("ressources/tree/etc/selinux/modules/veeam_repository_custom_policy.pp")
                copy_file("ressources/tree/etc/selinux/modules/veeam_transport_custom_policy.pp")

                values["[is_a_veeam_client]"] = "true"
                values["[veeam_backups_mount_point]"] = data["veeam_stockage"]["veeam_backup_directory"] 
                values["[veeam_user]"] = data["veeam_stockage"]["veeam_user"]

                values["[rich_rules]"] += [f'firewall-cmd --permanent --zone=public --add-rich-rule=\'rule family="ipv4" source address="{data["veeam_stockage"]["veeam_server"]}" port port="22" protocol="tcp" accept\'']
                values["[rich_rules]"] += [f'firewall-cmd --permanent --zone=public --add-rich-rule=\'rule family="ipv4" source address="{data["veeam_stockage"]["veeam_server"]}" port port="6162" protocol="tcp" accept\'']

                for agent in data["veeam_stockage"]["veeam_agents"]:
                    values["[rich_rules]"] += [f'firewall-cmd --permanent --zone=public --add-rich-rule=\'rule family="ipv4" source address="{agent}" port port="2500-3300" protocol="tcp" accept\'']

                copy_file("ressources/tree/etc/yum.repos.d/veeam-local.repo")

                values["[package_list_to_install]"] += ["veeam"]

            else:
                values["[is_a_veeam_client]"] = "false"

        ########

            if "rsyslog_server" in data.keys():

                for log_sender in data["rsyslog_server"]["log_senders"]:

                    port = log_sender["port"]
                    protocol = log_sender["protocol"]
                    senders = log_sender["senders"]

                    for sender in senders:
                        values["[rich_rules]"] += [f'firewall-cmd --permanent --zone=public --add-rich-rule=\'rule family="ipv4" source address="{sender}" port port="{port}" protocol="{protocol}" accept\'']

        ########

            if "zabbix" in data.keys():

                values["[is_a_zabbix_server]"] = "true"
                values["[has_packages]"] = "true"
                values["[package_list_to_install]"] += ["zabbix-server-mysql", "zabbix-web-mysql", "zabbix-apache-conf", "mariadb-server", "net-snmp-utils", "net-snmp-perl", "net-snmp", "mod_ssl", "policycoreutils-python-utils", "httpd"]
                values["[service_list_to_enable]"] += ["mariadb", "zabbix-server", "httpd", "php-fpm", "snmptrapd"]
                values["[zabbix_db_name]"] = data["zabbix"]["db_name"]
                values["[zabbix_db_user]"] = data["zabbix"]["db_user"]
                values["[zabbix_db_password]"] = data["zabbix"]["db_password"]

                for web_administrator in data["zabbix"]["web_administrators"]:
                    values["[rich_rules]"] += [f'firewall-cmd --permanent --zone=public --add-rich-rule=\'rule family="ipv4" source address="{web_administrator}" port port="443" protocol="tcp" accept\'']

                if "trap_senders" in data["zabbix"].keys():
                    for trap_sender in data["zabbix"]["trap_senders"]:
                        values["[rich_rules]"] += [f'firewall-cmd --permanent --zone=public --add-rich-rule=\'rule family="ipv4" source address="{trap_sender}" port port="162" protocol="udp" accept\'']

                CA_certificate = data["zabbix"]["CA_certificate"]

                copy_file(f'configurations/{chosen_configuration_name}/xca/certificates/{CA_certificate}', f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}/tree/etc/pki/tls/certs/ca.crt')
                copy_file(f'configurations/{chosen_configuration_name}/xca/certificates/{hostname}.crt', f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}/tree/etc/pki/tls/certs/ssl.crt')
                copy_file(f'configurations/{chosen_configuration_name}/xca/private_keys/{hostname}.key', f'configurations/{chosen_configuration_name}/hosts/{domain}/{hostname}/tree/etc/pki/tls/private/ssl.key')

            else:
                values["[is_a_zabbix_server]"] = "false"

        ########

            if "ad" in data.keys():

                values["[server_has_ad]"] = "true"
                values["[ad_server_ip]"] = data["ad"]["ad_ip"]
                values["[ad_server_hostname]"] = data["ad"]["ad_hostname"]
                values["[domain]"] = data["ad"]["domain"].upper()
                values["[ad_user]"] = data["ad"]["user"]
                values["[ad_user_password]"] = data["ad"]["password"]
                values["[rule_list]"] = '"' + '" "'.join([
                    "ad_gpo_access_control = permissive", 
                    "ad_gpo_ignore_unreadable = True"
                ]) + '"'

            else:
                values["[server_has_ad]"] = "false"

        ########

            if "samba_server" in data.keys():

                values["[is_a_samba_server]"] = "true"
                values["[samba_user]"] = "puce"
                values["[samba_mount_point]"] = "/mnt/samba"
                values["[samba_user_shell]"] = "/sbin/nologin"
                values["[has_packages]"] = "true"
                values["[package_list_to_install]"] += ["samba", "samba-winbind", "samba-winbind-modules"]  # "realmd", "oddjob", "adcli", "authselect-compat"
                values["[service_list_to_enable]"] += ["samba", "winbind"]
                values["[service_list_to_add_to_firewall]"] += ["samba"]

            else:
                values["[is_a_samba_server]"] = "false"

        ########

            if "ntp" in data.keys():

                values["[has_services]"] = "true"
                values["[service_list_to_enable]"] += ["chronyd"]

        ########

            if "rsyslog" in data.keys():

                rsyslog_server = data["rsyslog"]["rsyslog_server"]

                values["[has_packages]"] = "true"
                values["[package_list_to_install]"] += ["rsyslog", "rsyslog-gnutls", "policycoreutils-python-utils"]
                values["[service_list_to_enable]"] += ["rsyslog"]       

        ########

            if "snmp" in data.keys():

                if "server_address" in data["snmp"].keys():  
                    values["[rich_rules]"] += [f'firewall-cmd --permanent --zone=public --add-rich-rule=\'rule family="ipv4" source address="{data["snmp"]["server_address"]}" port port="161" protocol="udp" accept\'']

                values["[has_services]"] = "true"
                values["[server_has_snmp]"] = "true"
                values["[service_list_to_enable]"] += ["snmpd"]
                values["[hash_algo]"] = data["snmp"]["hash_algo"]
                values["[hash_password]"] = data["snmp"]["hash_password"]
                values["[crypto_algo]"] = data["snmp"]["crypto_algo"]
                values["[crypto_password]"] = data["snmp"]["crypto_password"]
                values["[snmp_user]"] = data["snmp"]["snmp_user"]

            else:
                values["[server_has_snmp]"] = "false"

        ########

            if "samba" in data.keys():

                values["[has_packages]"] = "true"
                values["[package_list_to_install]"] += ["samba"]
                values["[service_list_to_enable]"] += ["smb"]
                values["[service_list_to_add_to_firewall]"] += ["samba"]

        ########

            if "firewall" in data.keys():

                if "services" in data["firewall"].keys():

                    values["[has_services]"] = "true"
                    values["[service_list_to_add_to_firewall]"] += data["firewall"]["services"]

                if "rules" in data["firewall"].keys():

                    for rule in data["firewall"]["rules"]:
                        values["[rich_rules]"] += [f'firewall-cmd --permanent --zone=public --add-rich-rule=\'rule family="ipv4" source address="{rule["address"]}" port port="{rule["port"]}" protocol="{rule["protocol"]}" accept\'']

        ########

            if "network" in data.keys():

                # for "admin" in ["admin", "metier", ...]
                for interface in data["network"].keys():

                    if ("disabled" in interface) or ("ilo" in interface):
                        continue

                    values["[interface_list_to_add_to_firewall]"].append(data["network"][interface]["interface"]["device"])

                    if "address" in data["network"][interface]["interface"].keys():

                        values["[restart_network_interfaces]"] += [f'ifdown {interface}\nifup {interface}']

                    if "routes" in data["network"][interface].keys():

                        for route in data["network"][interface]["routes"]:

                            dest, mask, gw = route

                            if mask == "255.255.255.255":
                                values["[ping_static_routes]"] += [f'ping -a -c 3 {dest}']

                        values["[ping_static_routes]"] += [f'ping -a -c 3 {gw}']

            if len(values["[service_list_to_add_to_firewall]"]) > 1:
                values["[service_list_to_add_to_firewall]"] = '{' + ",".join(values["[service_list_to_add_to_firewall]"]) + '}'
                values["[has_services_to_add]"] = "true"

            elif len(values["[service_list_to_add_to_firewall]"]) == 1:
                values["[service_list_to_add_to_firewall]"] = values["[service_list_to_add_to_firewall]"][0]
                values["[has_services_to_add]"] = "true"

            else:
                values["[service_list_to_add_to_firewall]"] = ""

            if len(values["[service_list_to_remove_from_firewall]"]) > 1:
                values["[service_list_to_remove_from_firewall]"] = '{' + ",".join(values["[service_list_to_remove_from_firewall]"]) + '}'
                values["[has_services_to_remove]"] = "true"

            elif len(values["[service_list_to_remove_from_firewall]"]) == 1:
                values["[service_list_to_remove_from_firewall]"] = values["[service_list_to_remove_from_firewall]"][0]
                values["[has_services_to_remove]"] = "true"

            else:
                values["[service_list_to_remove_from_firewall]"] = ""

            if len(values["[interface_list_to_add_to_firewall]"]) == 1:
                values["[interface_list_to_add_to_firewall]"] = values["[interface_list_to_add_to_firewall]"][0]
            elif len(values["[interface_list_to_add_to_firewall]"]) > 1:
                values["[interface_list_to_add_to_firewall]"] = "{" + ",".join(values["[interface_list_to_add_to_firewall]"]) + "}"

            values["[port_list_to_add_to_firewall]"] = ",".join(values["[port_list_to_add_to_firewall]"])

            values["[ping_static_routes]"] = "\n".join(values["[ping_static_routes]"])
            values["[restart_network_interfaces]"] = "\n".join(values["[restart_network_interfaces]"])

            values["[rich_rules]"] = "\n".join(values["[rich_rules]"])

            values["[service_list_to_enable]"] = " ".join(values["[service_list_to_enable]"])
            values["[package_list_to_install]"] = " ".join(values["[package_list_to_install]"])
            values["[group_list_to_install]"] = " ".join(values["[group_list_to_install]"])

            configure_file(source, values)

        #
        #######################################  I P  #####################################
        #

            if "network" in data.keys():

                # INTERFACE
                for interface, details in data["network"].items():

                    if data["os"] == "centos":

                        source = Path(f'ressources/tree/etc/sysconfig/network-scripts/ifcfg')

                        values = {
                            "[ip_config]": f'NAME="{interface}"\nTYPE={details["interface"]["type"]}\nDEVICE={details["interface"]["device"]}\n'
                        }

                        # ON BOOT
                        if ("on_boot" in details["interface"].keys()) and (details["interface"]["on_boot"] == "no"):

                            values["[ip_config]"] += "ONBOOT=no\n"

                        else:

                            values["[ip_config]"] += "ONBOOT=yes\n"

                        # MAC
                        if "mac" in details["interface"].keys():

                            values["[ip_config]"] += f'MAC={details["interface"]["mac"]}\n'

                        # ADDRESS
                        if "address" in details["interface"].keys():

                            values["[ip_config]"] += f'IPADDR={details["interface"]["address"]}\n'

                        # MASK
                        if "mask" in details["interface"].keys():

                            values["[ip_config]"] += f'PREFIX={details["interface"]["mask"]}\n'

                        # DEFAULT GATEWAY
                        if "default_gateway" in details["interface"].keys():

                            values["[ip_config]"] += f'GATEWAY={details["interface"]["default_gateway"]}\n'

                        # DNS
                        if "dns" in details["interface"].keys():

                            # for (0, "10.0.0.1") in ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
                            for index, dns in enumerate(details["interface"]["dns"]):
                                # values["[dns_1]"] = "10.0.0.1"
                                values["[ip_config]"] += f'DNS{index+1}={dns}\n'

                        if "slaves" in details["interface"].keys():

                            values["[ip_config]"] += "BOUNDING_OPTS=\"downdelay=0 miimon=100 mode=active-backup updelay=0\"\nBOUNDING_MASTER=yes"

                            for slave in details["interface"]["slaves"]:

                                slave_values = {
                                    "[ip_config]": f'TYPE=Ethernet\nNAME={slave}\nDEVICE={slave}\nONBOOT=no'
                                }

                                configure_file(source, slave_values, f'{source}-{slave}')

                                slave_values = {
                                    "[ip_config]": f'TYPE=Ethernet\nNAME={slave}\nDEVICE={slave}\nONBOOT=yes\nNM_CONTROLED=no\nSLAVE=yes\nMASTER={details["interface"]["device"]}'
                                }

                                configure_file(source, slave_values, f'{source}-{slave}-1')

                        configure_file(source, values, f'{source}-{interface}')

                        # ROUTES
                        if "routes" in details.keys():

                            source = Path(f'ressources/tree/etc/sysconfig/network-scripts/route')
                            values = {
                                "[routes]": ""
                            }

                            # for (0, ("192.168.0.1", "255.255.255.0", "10.0.0.254")) in [("192.168.0.1", "255.255.255.0", "10.0.0.254"), ...]
                            for index, route in enumerate(details["routes"]):
                                dest, mask, gw = route
                                # 
                                # values["[routes]"] = 
                                # "ADDRESS0=192.168.0.1
                                #  NETMASK0=255.255.255.0
                                #  GATEWAY0=10.0.0.254
                                #  ..."
                                # 
                                values["[routes]"] += f'ADDRESS{index}={dest}\nNETMASK{index}={mask}\nGATEWAY{index}={gw}\n'

                            configure_file(source, values, f'{source}-{interface}')

        #
        #####################################  S W I T C H  ###############################
        #

        if data["os"] == "cisco":

            values = {
                "[hostname]": hostname.split(".")[0],
                "[domain]": hostname.split(".", 1)[1]
            }

            if "snmp" in data.keys():

                values.update({

                    "[domain]": data["domain"],
                    "[hash_algo]": data["snmp"]["hash_algo"],
                    "[hash_password]": data["snmp"]["hash_password"],
                    "[crypto_algo]": data["snmp"]["crypto_algo"],
                    "[crypto_password]": data["snmp"]["crypto_password"],
                    "[snmp_user]": data["snmp"]["snmp_user"],
                    "[template]": data["snmp"]["templates"][0],
                    "[group]": data["snmp"]["groups"][0],
                    "[listening_address]": data["snmp"]["listening_address"]

                })

            if "ssh" in data.keys():

                values.update({

                    "[ip_admin]": data["ssh"]["ip_admin"]

                })

            if "ntp" in data.keys():

                values.update({

                    "[chrony_server]": data["ntp"]["chrony_server"]

                })

            if "syslog" in data.keys():

                values.update({

                    "[host-syslog]": data["syslog"]["host-syslog"],
                    "[vlan-syslog]": data["syslog"]["vlan-syslog"]

                })

            if "radius" in data.keys():

                values.update({

                    "[name_radius]": data["radius"]["name_radius"],
                    "[ip_radius]": data["radius"]["ip_radius"]

                })

            if "gateway" in data.keys():

                values.update({

                    "[ip_gateway]": data["gateway"]["ip_gateway"] 

                })

            if "mac_adresse" in data.keys():

                values.update({

                    "[vm_srv_ad]": data["mac_adresse"]["vm_rv_ad"],
                    "[vm_srv_surv]": data["mac_adresse"]["vm_srv_surv"],
                    "[vm_srv_sauv]": data["mac_adresse"]["vm_srv_sauv"],
                    "[vm_exploit_1]": data["mac_adresse"]["vm_exploit_1"],
                    "[vm_exploit_2]": data["mac_adresse"]["vm_exploit_2"],
                    "[vm_exploit_3]": data["mac_adresse"]["vm_exploit_3"],
                    "[vm_exploit_4]": data["mac_adresse"]["vm_exploit_4"],
                    "[vm_exploit_5]": data["mac_adresse"]["vm_exploit_5"],
                    "[vm_exploit_6]": data["mac_adresse"]["vm_exploit_6"],
                    "[vm_exploit_7]": data["mac_adresse"]["vm_exploit_7"],
                    "[vm_exploit_simu]": data["mac_adresse"]["vm_exploit_simu"],
                    "[vm_puce]": data["mac_adresse"]["vm_puce"],
                    "[vm_srv_generation]": data["mac_adresse"]["vm_srv_generation"],
                    "[vm_srv_slp]": data["mac_adresse"]["vm_srv_slp"],
                    "[pc_client_1]": data["mac_adresse"]["pc_client_1"],
                    "[srv_infra]": data["mac_adresse"]["srv_infra"],
                    "[vm_srv_ad_adm]": data["mac_adresse"]["vm_srv_ad_adm"],
                    "[vm_srv_sauv_adm]": data["mac_adresse"]["vm_srv_sauv_adm"],
                    "[vm_srv_surv_adm]": data["mac_adresse"]["vm_srv_surv_adm"],
                    "[vm_srv_vcenter]": data["mac_adresse"]["vm_srv_vcenter"],
                    "[srv_infra_ilo]": data["mac_adresse"]["srv_infra_ilo"],
                    "[srv_stockage]": data["mac_adresse"]["srv_stockage"],
                    "[srv_stockage_adm]": data["mac_adresse"]["srv_stockage_adm"],
                    "[srv_stockage_ilo]": data["mac_adresse"]["srv_stockage_ilo"],
                    "[srv_pool_exploitation]": data["mac_adresse"]["srv_pool_exploitation"],
                    "[srv_exploit_1_adm]": data["mac_adresse"]["srv_exploit_1_adm"],
                    "[srv_exploit_2_adm]": data["mac_adresse"]["srv_exploit_2_adm"],
                    "[srv_exploit_3_adm]": data["mac_adresse"]["srv_exploit_3_adm"],
                    "[srv_exploit_4_adm]": data["mac_adresse"]["srv_exploit_4_adm"],
                    "[srv_exploit_5_adm]": data["mac_adresse"]["srv_exploit_5_adm"],
                    "[srv_exploit_6_adm]": data["mac_adresse"]["srv_exploit_6_adm"],
                    "[srv_exploit_7_adm]": data["mac_adresse"]["srv_exploit_7_adm"],
                    "[srv_exploit_simu_adm]": data["mac_adresse"]["srv_exploit_simu_adm"],
                    "[srv_pool_exploitation_ilo]": data["mac_adresse"]["srv_pool_exploitation_ilo"],
                    "[srv_donnees]": data["mac_adresse"]["srv_donnees"],
                    "[srv_generation_adm]": data["mac_adresse"]["srv_generation_adm"],
                    "[vm_puce_adm]": data["mac_adresse"]["vm_puce_adm"],
                    "[vm_srv_slp_adm]": data["mac_adresse"]["vm_srv_slp_adm"],
                    "[srv_donnees_ilo]": data["mac_adresse"]["srv_donnees_ilo"],
                    "[pc_client_1_adm]": data["mac_adresse"]["pc_client_1_adm"],
                    "[srv_bdd_ilo]": data["mac_adresse"]["srv_bdd_ilo"],
                    "[srv_bdd]": data["mac_adresse"]["srv_bdd"],
                    "[srv_bdd_adm]": data["mac_adresse"]["srv_bdd_adm"],
                    "[pc_admin_1]": data["mac_adresse"]["pc_admin_1"]

                })

                if "pc_client_2_adm" in data["mac_adresse"].keys():
                    values.update({
                        "[pc_client_2_adm]": data["mac_adresse"]["pc_client_2_adm"]
                    })

                if "pc_client_3_adm" in data["mac_adresse"].keys():
                    values.update({
                        "[pc_client_3_adm]": data["mac_adresse"]["pc_client_3_adm"]
                    })

                if "pc_client_2" in data["mac_adresse"].keys():
                    values.update({
                        "[pc_client_2]": data["mac_adresse"]["pc_client_2"]
                    })

                if "pc_client_3" in data["mac_adresse"].keys():
                    values.update({
                        "[pc_client_3]": data["mac_adresse"]["pc_client_3"]
                    })

            if "ethernet_ports" in data.keys():

                values["[port_def]"] = []

                for port_id, ethernet_port in data["ethernet_ports"].items():
                    values["[port_def]"].append(f"interface GigabitEthernet1/0/{port_id}")
                    values["[port_def]"].append(f' shutdown') 

                    if "description" in ethernet_port.keys():
                        values["[port_def]"].append(f' description {ethernet_port["description"]}') 

                    if "vlan" in ethernet_port.keys(): 
                        values["[port_def]"].append(f' switchport access vlan {ethernet_port["vlan"]}')
                        values["[port_def]"].append(" mode access")

                    if "mac_addresses" in ethernet_port.keys():
                        values["[port_def]"].append(" switchport port-security")
                        values["[port_def]"].append(" switchport port-security violation restrict")
                        values["[port_def]"].append(f' switchport port-security maximum {len(ethernet_port["mac_addresses"])}')

                        for macad in ethernet_port["mac_addresses"]:
                            values["[port_def]"].append(f' switchport port-security mac-address {macad}')

                    if "trunk" in ethernet_port.keys():
                        values["[port_def]"].append(f' switchport trunk native vlan {ethernet_port["trunk"]["native_vlan"]}')
                        values["[port_def]"].append(f' switchport trunk allowed vlan {",".join(ethernet_port["trunk"]["allowed_vlan"])}')
                        values["[port_def]"].append(" switchport mode trunk")

                    values["[port_def]"].append(" switchport nonegotiate")
                    values["[port_def]"].append(" no vtp")

                    if "trunk" in ethernet_port.keys():
                        values["[port_def]"].append(" channel-group 1 mode passive")

                    if ("shutdown" in ethernet_port.keys()) and not (ethernet_port["shutdown"]):
                        values["[port_def]"].append(" no shutdown")

                    values["[port_def]"].append("!")

                values["[port_def]"] = "\n".join(values["[port_def]"])

            if "vlan" in data.keys():

                values.update({

                    "[vlan-serveur]": data["vlan"]["vlan-serveur"],
                    "[vlan-client]": data["vlan"]["vlan-client"],
                    "[vlan-maintenance]": data["vlan"]["vlan-maintenance"],
                    "[vlan-infra]": data["vlan"]["vlan-infra"],
                    "[vlan-admin]": data["vlan"]["vlan-admin"],
                    "[vlan-quarantaine]": data["vlan"]["vlan-quarantaine"],
                    # "[vlan-snef_net]": data["vlan"]["vlan-snef_net"]
                })

            configure_file("ressources/cisco/SW1.CNCDTDS3.LOCAL-2021-11-19.conf", values)

        #
        #####################################  PARE FEU ###############################
        #

        if data["os"] == "palo-alto":

            values = {
                "[syslog]": "",
                "[DEVICE]": "",
                "[NTP]": "",
                "[BAN]": "",
                "[CERTIF]": "",
                "[RADIUS]": "",
                "[vlan]": "",
                "[flux]": "",
                "[objecty]": ""
            }

            for syslog in data["syslog"]:

                values["[syslog]"] += f'''
                <entry name="{syslog["name"]}">
                  <transport>SSL</transport>
                  <port>6514</port>
                  <format>IETF</format>
                  {"".join([f"<server>{server}</server>" for server in syslog["server"]])} 
                  <facility>LOG_USER</facility>
                </entry>'''

            for DEVICE in data["DEVICE"]:

                values["[DEVICE]"] += f'''
              {"".join([f"<ip-address>{ip_address}</ip-address>" for ip_address in DEVICE["ip_address"]])}
              {"".join([f"<netmask>{netmask}</netmask>" for netmask in DEVICE["netmask"]])}
              <update-schedule>
                <threats>
                  <recurring>
                    <weekly>
                      <day-of-week>wednesday</day-of-week>
                      <at>01:02</at>
                      <action>download-only</action>
                    </weekly>
                  </recurring>
                </threats>
              </update-schedule>
              <timezone>Europe/Paris</timezone>
              <service>
                <disable-telnet>yes</disable-telnet>
                <disable-http>yes</disable-http>
                <disable-icmp>yes</disable-icmp>
              </service>
              <hostname>CF1</hostname>
              <type>
                <static/>
              </type>
              {"".join([f"<default-gateway>{default_gateway}</default-gateway>" for default_gateway in DEVICE["default_gateway"]])} 
                  '''

            for NTP in data["NTP"]:

                values["[NTP]"] += f'''
                  {"".join([f"<ntp-server-address>{ntp_server_address}</ntp-server-address>" for ntp_server_address in NTP["ntp_server_address"]])} 
                  '''
            for BAN in data["BAN"]:

                values["[BAN]"] += f'''
                  {"".join([f"<login-banner>{login_banner}</login-banner>" for login_banner in BAN["login_banner"]])} 
                  '''

            for CERTIF in data["CERTIF"]:

                values["[CERTIF]"] += f'''
          <entry name="{CERTIF["name"]}">
            {"".join([f"<subject-hash>{subject_hash}</subject-hash>" for subject_hash in CERTIF["subject_hash"]])}
            {"".join([f"<issuer-hash>{issuer_hash}</issuer-hash>" for issuer_hash in CERTIF["issuer_hash"]])}
            {"".join([f"<not-valid-before>{not_valid_before}</not-valid-before>" for not_valid_before in CERTIF["not_valid_before"]])}
            {"".join([f"<issuer>{issuer}</issuer>" for issuer in CERTIF["issuer"]])}
            {"".join([f"<not-valid-after>{not_valid_after}</not-valid-after>" for not_valid_after in CERTIF["not_valid_after"]])}
            {"".join([f"<common-name>{common_name}</common-name>" for common_name in CERTIF["common_name"]])}
            {"".join([f"<expiry-epoch>{expiry_epoch}</expiry-epoch>" for expiry_epoch in CERTIF["expiry_epoch"]])}
            {"".join([f"<ca>{ca}</ca>" for ca in CERTIF["ca"]])}
            {"".join([f"<subject>{subject}</subject>" for subject in CERTIF["subject"]])}
            {"".join([f"<public-key>{public_key}</public-key>" for public_key in CERTIF["public_key"]])}
            {"".join([f"<algorithm>{algorithm}</algorithm>" for algorithm in CERTIF["algorithm"]])}'''

                values["[CERTIF]"] += ("".join([f"\n<private-key>{private_key}</private-key>" for private_key in CERTIF["private_key"]]) if "private_key" in CERTIF.keys() else "")  
                values["[CERTIF]"] += '''
            </entry> '''

            for RADIUS in data["RADIUS"]:
                values["[RADIUS]"] += f'''
                      <entry name="{RADIUS["name"]}">
              <protocol>
                <PAP/>
              </protocol>
              <server>
                <entry name="VM-SRV-SAUV-ADM">
                  <secret>-AQ==NaLrhq6o8PKzHgV9JR1TcSbuVWg=sLtMJKpd6bd4I4A5hT9R7A==</secret>
                  <port>1812</port>
                  {"".join([f"<ip-address>{ip_address}</ip-address>" for ip_address in RADIUS["ip_address"]])} 
                </entry>
              </server>
              <admin-use-only>yes</admin-use-only>
              <timeout>10</timeout>
            </entry>'''

            for vlan in data["vlan"]:

                values["[vlan]"] += f'''
                      <entry name="{vlan["name"]}">
                        <nexthop>
                          {"".join([f"<ip-address>{ip_address}</ip-address>" for ip_address in vlan["ip_address"]])} 
                        </nexthop> 
                        <path-monitor> 
                          <enable>no</enable>
                          <failure-condition>any</failure-condition>
                          <hold-time>2</hold-time>
                        </path-monitor> 
                        <metric>10</metric>
                        {"".join([f"<destination>{destination}</destination>" for destination in vlan["destination"]])} 
                        <route-table>
                          <both/> 
                        </route-table> 
                      </entry>'''

            for flux in data["flux"]:

                values["[flux]"] += f'''
                      <entry name="{flux["name"]}">
                        <to>
                          {"".join([f"<member>{member}</member>" for member in flux["zones_destination"]])} 
                        </to> 
                        <from> 
                          {"".join([f"<member>{member}</member>" for member in flux["zones_source"]])} 
                        </from> 
                        <source> 
                          '''
                values["[flux]"] += "\n                      ".join([f"<member>{member}</member>" for member in flux["sources"]])
                values["[flux]"] += '''
                        </source> 
                        <destination> 
                          '''
                values["[flux]"] += "\n                      ".join([f"<member>{member}</member>" for member in flux["destinations"]])
                values["[flux]"] += '''
                        </destination> 
                        <source-user> 
                          <member>any</member> 
                        </source-user>  
                        <application>
                          '''
                values["[flux]"] += "\n                      ".join([f"<member>{member}</member>" for member in flux["applications"]])
                values["[flux]"] += '''
                        </application> 
                        <service>
                          '''
                values["[flux]"] += "\n                      ".join([f"<member>{member}</member>" for member in flux["services"]]) 
                values["[flux]"] += f'''
                        </service> 
                        <hip-profiles> 
                          <member>any</member> 
                        </hip-profiles>
                        <action>{flux["action"]}</action>
                        <disabled>{flux["disabled"]}</disabled>
                        <category> 
                          <member>any</member> 
                        </category>'''

                values["[flux]"] += ("\n                    <negate-source>no</negate-source>" if "negate-source" in flux.keys() else "")
                values["[flux]"] += ("\n                    <negate-destination>no</negate-destination>" if "negate-source" in flux.keys() else "")
                values["[flux]"] += ("\n                    <log-start>yes</log-start>" if "log-start" in flux.keys() else "")
                values["[flux]"] += ("\n                    <log-setting>CNCDTDS3_LOGS</log-setting>" if "log-setting" in flux.keys() else "")
                values["[flux]"] += '''
                      </entry>'''

            for objecty in data["objecty"]:

                values["[objecty]"] += f'''
                <entry name="{objecty["name"]}">
                  {"".join([f"<ip-netmask>{ip_netmask}</ip-netmask>" for ip_netmask in objecty["ip_netmask"]])}'''
                values["[objecty]"] += ("".join([f"<description>{description}</description>" for description in objecty["description"]]) if "description" in objecty.keys() else "") 
                values["[objecty]"] += '''
                </entry>'''

            configure_file("ressources/palo-alto/candidate-config.xml", values)
