#!/usr/bin/env bash

###############################  F U N C T I O N S  ###############################

#
#
# ############################################################################################
#
# #####
# #####    P A Q U E T S  
# #####
#
#

function title {

    clear

    echo -e "\n\n############################################################################################\n\n######\n######\t$1\n######\n\n"

}


#
#
# #############################################
#
# ###
# ###    INSTALLATION DES PAQUETS  
# ###
#
#

function subtitle {

    echo -e "\n#############################################\n\n###\t$1\n"

}


#
#   Pose une question jusqu'a ce que la réponse soit Y, y, N, n ou ENTREE
#
# Commande :
#
# ask "Voulez-vous redémarrer la machine ?" "N" "reboot" "return 0"
#
# Arguments :
#
# $1 : Question -> Voulez-vous redémarrer la machine ?
# $2 : Valeur par défaut (Y ou N) -> Y = OUI, N = NON
# $3 : Si oui (commande) -> echo "vous avez dis oui !"
# $4 : Si non (commande) -> echo "vous avez dis non !"
#
# Résultat : 
#
# #    Voulez-vous redémarrer la machine ? [y/N]
#

function ask {

    if [ $2="Y" ]
    then
        options="[Y/n]"

    elif [ $2="N" ]
    then
        options="[y/N]"
    fi

    echo -n -e "\n#\t"
    read -t 10 -p "$1 $options: " choice
    echo ""

    if [ -z "$choice" ]
    then
        choice="$2"
    fi

    while true;
    do
        case $choice in
            [Yy]*) eval $3 ; return 0 ;;  
            [Nn]*) eval $4 ; return 0 ;;
        esac
    done
}

function custom_pause {

    echo -n -e "\n#\t"
    read -t 10 -p "Passage automatique vers la configuration suivante dans 10 secondes..."
    echo ""
} 

function partitioning {

    title "P A R T I T I O N N E M E N T"

    subtitle "ANCIEN PARTITIONNEMENT"
    lvdisplay -C
    df -h
    lsblk

    subtitle "EXTENSION DES VOLUMES LOGIQUES"
    swapoff -a
    [partitions]
    swapon -va

    subtitle "NOUVEAU PARTITIONNEMENT"
    lvdisplay -C
    df -h
    lsblk

    custom_pause
}

function update_hostname {

    title "N O M   D' H O T E"

    subtitle "MISE A JOUR DU NOM D'HOTE"
    hostnamectl set-hostname [hostname]
}

function update_tree {

    title "A R B O R E S C E N C E"

    subtitle "LISTE DES ANCIENNES CONFIGURATIONS RESEAUX"
    ls -la /etc/sysconfig/network-scripts/

    subtitle "SUPPRESSION DES CONFIGURATIONS RESEAUX"
    rm -fv /etc/sysconfig/network-scripts/* 

    subtitle "LISTE DES ANCIENTS DEPOTS LOCAUX"
    yum repolist

    subtitle "SUPPRESSION DES DEPOTS LOCAUX"
    rm -fv /etc/yum.repos.d/* 

    subtitle "COPIE DE LA NOUVELLE ARBORESCENCE"
    cp -rvu tree/* /

    subtitle "LISTE DES NOUVEAUX DEPOTS LOCAUX"
    yum repolist

    subtitle "LISTE DES PACKETS DISPONIBLES"
    yum list available

    custom_pause 
}

function download_packages {

    title "P A Q U E T S"

    subtitle "MISE-A-JOUR DES PAQUETS INSTALLES"
    yum update -y

    subtitle "SUPPRESSION DES DEPOTS LOCAUX AJOUTES"
    rm -fv /etc/yum.repos.d/CentOS-Linux-*

    subtitle "INSTALLATION DES PAQUETS"
    yum install -y [package_list_to_install]

    custom_pause
}

function download_groups {

    title "G R O U P S"

    subtitle "INSTALLATION DES GROUPES"
    yum groupinstall -y [group_list_to_install]

    custom_pause
}

function update_setuid {

    title "P E R M I S S I O N S"

    subtitle "DESACTIVATION DU BIT SETUID"

    # Source : https://www.ssi.gouv.fr/uploads/2016/01/linux_configuration-fr-v1.2.pdf, chapitre 6.5.3
    file_list=("/bin/mount" "/bin/netreport" "/bin/ping6" "/bin/umount" "/sbin/mount.nfs4" "/sbin/mount.nfs" "/sbin/umount.nfs4" "/sbin/umount.nfs" "/usr/bin/at" "/usr/bin/chage" "/usr/bin/chfn" "/usr/bin/chsh" "/usr/bin/locate" "/usr/bin/fusermount" "/usr/bin/mail" "/usr/bin/procmail" "/usr/bin/rcp" "/usr/bin/rlogin" "/usr/bin/rsh" "/usr/bin/screen" "/usr/bin/wall" "/usr/lib/openssh/ssh-keysign" "/usr/lib/pt_chown" "/usr/sbin/exim4" "/usr/sbin/suexec" "/usr/sbin/traceroute" "/usr/sbin/traceroute6" "/usr/libexec/utempter/utempter" "/usr/lib/dbus-1.0/dbus-daemon-launch-helper" "/usr/bin/pkexec" "/usr/bin/crontab" "/usr/sbin/grub2-set-bootflag" "/usr/sbin/pam_timestamp_check" "/usr/libexec/openssh/ssh-keysign")

    for file in "${file_list[@]}"
    do
        if [ -f "$file" ]; then
            chmod u-s $file
            chmod g-s $file
            echo "Bit setUID et setGID désactivés pour $file"
        fi
    done

    custom_pause
}

function add_groups {

    title "G R O U P S"

    subtitle "AJOUT DES GROUPES LOCAUX"
    [add_groups]

    custom_pause
}

function add_users {

    title "U S E R S"

    subtitle "AJOUT DES UTILISATEURS LOCAUX"
    [add_users]

    custom_pause
}

function install_modules {

    title "M O D U L E S"

    subtitle "INSTALLATION DES MODULES SELINUX"
    semodule -i /etc/selinux/modules/*

    subtitle "LISTE DES MODULES SELINUX"
    semodule --list-modules=full | grep 400

    subtitle "EMPREINTE DES MODULES PERSONNALISES"
    md5sum /etc/selinux/modules/*

    custom_pause
}

function restart_services {

    title "S E R V I C E S   [ 1 / 2 ]"
    systemctl enable [service_list_to_enable]

    subtitle "DESACTIVATION DES SERVICES"
    systemctl disable [service_list_to_disable]

    subtitle "DEMARRAGE DES SERVICES"
    systemctl restart [service_list_to_enable]

    subtitle "VERIFICATION DU STATUS DE SERVICES"
    systemctl status [service_list_to_enable]

    custom_pause
}

function configure_networks {

    title "R E S E A U X"

    subtitle "MONTAGE DES CARTES RESEAUX"
    [restart_network_interfaces]

    subtitle "REDEMARRAGE DU GESTIONNAIRE DE RESEAUX"
    systemctl restart NetworkManager

    subtitle "VERIFICATION DES CARTES RESEAUX"
    ip a

    subtitle "VERIFICATION DES ROUTES STATIQUES"
    ip r

    subtitle "VERIFICATION DE LA CONNECTIVITE VERS LES ROUTES STATIQUES"
    [ping_static_routes]

    custom_pause
}

function enable_gui {

    title "I N T E R F A C E   G R A P H I Q U E"

    subtitle "PARAMETRAGE DE L'INTERFACE GRAPHIQUE"
    systemctl set-default graphical
    systemctl enable gdm

    subtitle "MISE-A-JOUR DE LA CONFIGURATION SELINUX"
    setsebool -P deny_bluetooth 0
    setsebool -P deny_execmem 0
    setsebool -P selinuxuser_execstack 1

[skel]
    
    custom_pause
}

function configure_firewall {

    title "P A R E - F E U"

    subtitle "CONFIGURATION D'ORIGINE DU PARE-FEU"
    firewall-cmd --list-all

    subtitle "MISE-A-JOUR DE LA CIBLE"
    firewall-cmd --permanent --zone=public --set-target=default

    if [has_services_to_remove]
    then
        subtitle "SUPPRESSION DE SERVICES"
        firewall-cmd --permanent --zone=public --remove-service=[service_list_to_remove_from_firewall]
    fi

    if [has_services_to_add]
    then
        subtitle "AJOUT DE SERVICES"
        firewall-cmd --permanent --zone=public --add-service=[service_list_to_add_to_firewall]
    fi

    if [has_ports_to_open]
    then
        subtitle "AJOUTS DE PORTS"
        firewall-cmd --permanent --zone=public --add-port={[port_list_to_add_to_firewall]}
    fi

    subtitle "AJOUTS D'INTERFACES"
    firewall-cmd --permanent --zone=public --change-interface=[interface_list_to_add_to_firewall]

    subtitle "AJOUTS DE REGLES"
    [rich_rules]

    subtitle "ENREGISTREMENT DE LA NOUVELLE CONFIGURATION"
    firewall-cmd --reload

    subtitle "NOUVELLE CONFIGURATION DU PARE-FEU"
    firewall-cmd --list-all

    custom_pause
}

function join_domain {

    title "D O M A I N E"

    subtitle "AJOUT DE LA RESOLUTION STATIQUE"
    echo "[ad_server_ip] [ad_server_hostname].[domain]" >> /etc/hosts

    subtitle "TEST DE LA RESOLUTION DNS"
    net lookup [domain]

    subtitle "TEST DE LA CONNECTIVITE VERS LE SERVEUR ACTIVE DIRECTORY"
    ping -a -c 3 [domain]

    subtitle "DECOUVERTE DU DOMAINE"
    realm discover -v [domain]

    subtitle "INSCRIPTION AU DOMAINE"
    echo [ad_user_password] | realm join [domain] -v -U [ad_user] 

    subtitle "TEST DU DOMAINE"
    id [ad_user]@[domain]

    subtitle "CONFIGURATION DU MODULE SSSD"
    rule_list=([rule_list])

    for rule in "${rule_list[@]}"
    do
        echo $rule >> /etc/sssd/sssd.conf
    done

    subtitle "REDEMARRAGE DU MODULE SSSD"
    systemctl restart sssd

    custom_pause
}

function configure_snmp {

    title "S N M P"

    subtitle "ARRET DU SERVICE SNMP"
    systemctl stop snmpd
    
    subtitle "CREATION DE L'UTILISATEUR SNMP"
    net-snmp-create-v3-user -ro -a [hash_algo] -A [hash_password] -x [crypto_algo] -X [crypto_password] [snmp_user]
    
    subtitle "DEMARRAGE DU SERVICE SNMP"
    systemctl start snmpd
    
    subtitle "VERIFICATION DU SERVICE SNMP"
    systemctl status snmpd

    subtitle "VERIFICATION DES REMONTEES SNMP"
    snmpwalk -v 3 -l authPriv -a [hash_algo] -A [hash_password] -x [crypto_algo] -X [crypto_password] -u [snmp_user] localhost

    custom_pause
}

function configure_samba {
            
    title "S A M B A"

    subtitle "CREATION DU GROUPE PUCE"
    groupadd [samba_user]

    subtitle "CREATION DE L'UTILISATEUR PUCE"
    useradd --shell [samba_user_shell] -g [samba_user] -M [samba_user]

    subtitle "VERIFICATION DE L'UTILISATEUR"
    cat /etc/passwd | grep "[samba_user]"

    subtitle "CREATION DU DOSSIER PARTAGE"
    mkdir [samba_mount_point]

    subtitle "VERIFICATION DU DOSSIER PARTAGE"
    ls -la [samba_mount_point]

    subtitle "MODIFICATION DES REGLES SELINUX"
    chcon -t samba_share_t [samba_mount_point]

    # A AJOUTER DANS LE FICHIER PREPARATION
    #subtitle "JOINTURE WINBIND VERS AD"
    #echo [ad_user_password] | net ads join -U [ad_user]@[domain]

    custom_pause
}

function configure_zabbix {

    title "Z A B B I X"

    subtitle "DESACTIVATION DU MODULE SELINUX"
    setenforce 0

    subtitle "INSTALLATION DE MYSQL"
    mysql_secure_installation #echo "" | echo yes | echo cncccl2019 | echo cncccl2019 | echo yes | mysql_secure_installation

    subtitle "CREATION DE LA BASE DE DONNEES ZABBIX"
    mysql --password --execute="create database zabbixdb character set utf8 collate utf8_bin; grant all privileges on [zabbix_db_name].* to [zabbix_db_user]@localhost identified by '[zabbix_db_password]';"

    path=`pwd`
    cd /usr/share/doc/zabbix-server-mysql/
    zcat create.sql.gz | mysql --user="[zabbix_db_user]" --database="[zabbix_db_name]" --password="[zabbix_db_password]"

    chown -R adminsys:adminsys /etc/zabbix/
    chmod -R 755 /etc/zabbix/
    cd "$path"

    subtitle "MISE-A-JOUR DE LA CONFIGURATION SELINUX"
    setsebool -P httpd_can_connect_zabbix 1
    setsebool -P httpd_can_network_connect 1
    setsebool -P httpd_read_user_content 1
    setsebool -P zabbix_can_network 1

    subtitle "APPLICATION DES POLITIQUES SELINUX"
    semodule -i /etc/selinux/modules/zabbix_custom_policy.pp
    semodule -i /etc/selinux/modules/httpd_custom_policy.pp

    subtitle "ACTIVATION DU MODULE SELINUX"
    setenforce 1

    subtitle "MISE EN PLACE DES RECEVEURS SNMP"
    chmod a+x /usr/bin/zabbix_trap_receiver.pl

    custom_pause    
}

function configure_veeam {

    title "V E E A M"

    subtitle "CREATION DU REPERTOIRE DE SAUVEGARDES"
    mkdir -v -p [veeam_backups_mount_point]

    subtitle "MISE-A-JOUR DES DROITS D'ECRITURE"
    chown [veeam_user]@[domain] [veeam_backups_mount_point]

    subtitle "ELEVATION DU COMPTE DE SERVICE"
    echo "%[veeam_user]@[domain] ALL=(ALL) ALL" >> /etc/sudoers.d/domain_admins

    custom_pause
}

function update_pam {
    
    title "P A M"

    subtitle "ACTIVATION DES MODULES"
    authselect select sssd --force with-mkhomedir with-faillock --trace --warn
    systemctl restart sssd oddjobd

    # <!> Ajouter " winbind" après "sss files systemd" dans /etc/nsswitch.conf

    subtitle "VERIFICATION DE LA CONFIGURATION"
    cat /etc/pam.d/system-auth
    cat /etc/pam.d/password-auth

    subtitle "CORRECTION DU BUG DE MISE EN VEILLE"
    # Lors de l'installation de l'interface graphique XFCE, le sticky bit de unix_chkpwd est désactivé.
    # Il faut l'activer auquel cas le dévérouillage de l'écran échoue même avec le bon mot de passe
    chmod u+s /sbin/unix_chkpwd

    custom_pause
}

function configure_nfs {
    
    title "N F S"

    subtitle "CREATION DES DOSSIERS DE PARTAGE"
    [nfs_mount_point_name]

    subtitle "MODIFICATION DU PROPRIETAIRE DES DOSSIERS"
    [nfs_mount_point_owner]

    subtitle "MODIFICATION DES DROITS DES DOSSIERS"
    [nfs_mount_point_rights]

    custom_pause
}

function install_xca {
    
    title "X C A"

    subtitle "RESTRICTION DE L'ACCÈS À LA BASE DE DONNÉES"
    chown -R adminsys:wheel /usr/share/CNC_PKI
    chmod -R g+rwx /usr/share/CNC_PKI

    subtitle "MISE-À-JOUR DE LA VARIABLE D'ENVIRONNEMENT"
    export PATH="$PATH:/usr/local/bin/"
    chown -R adminsys:wheel /usr/local/bin/

    custom_pause
}

function configure_cron_tasks {

    subtitle "CONFIGURATION DES TACHES PLANNIFIEES"
    [cron_files]
    chmod 644 /var/spool/cron/*
}

function configure_scp_backups {

    subtitle "CONFIGURATION DES SAUVEGARDES"
    [scp_backups]
}

function configure_scp_backups_folders {

    subtitle "CONFIGURATION DES DOSSIER DE SAUVEGARDES"
    [scp_folders]
}

function install_vmrc {
    
    title "V M R C"

    subtitle "Installation du client VMRC"
    ./vmware/VMware-Remote-Console-12.0.0-17287072.x86_64.bundle

    custom_pause
}

function update_ssh_keys {

    title "S S H"

    subtitle "Installation des clés SSH"
    [ssh_keys]

    custom_pause
}

function main {

    clear

    echo "  __  __ ___ ___  ____   "
    echo " |  \/  |_ _/ _ \/ ___|  "
    echo " | |\/| || | | | \___ \  "
    echo " | |  | || | |_| |___) | "
    echo " |_|  |_|___\___/|____/  "

    date=`date`
    hostname=`hostname`
    path=`pwd`

    title "D E B U T   D E   L'I N S T A L L A T I O N"

    echo -e "\nConfiguration realisee le $date, par l'utilisateur $USER, sur la machine $hostname, depuis le dossier $path\n\n"

    custom_pause

    #################################  P A R T I T I O N S  ###############################

    if [has_partitioning]
    then    
        ask "Partitionner les disques ?" "Y" "partitioning" ""
    fi
    
    #################################  H O S T N A M E  ###############################

    ask "Mise a jour du nom d'hote ?" "Y" "update_hostname" ""

    #####################################  T R E E ####################################

    ask "Mettre a jour l'arborescence ?" "Y" "update_tree" ""

    #################################  P A C K A G E S  ###############################

    if [has_packages]
    then    
        ask "Telecharger les paquets manquants ?" "Y" "download_packages" ""
    fi

    ####################################  G R O U P S  #################################

    if [has_packet_groups]
    then
        ask "Télécharger les groupes manquants ?" "Y" "download_groups" ""
    fi

    ####################################  S E T U I D  ################################

    ask "Desactiver le bit setuid sur les executables non utilises ?" "Y" "update_setuid" ""

    ####################################  G R O U P S  ################################

    if [has_groups]
    then
        ask "Ajouter les groupes manquants ?" "Y" "add_groups" ""
    fi

    #####################################  U S E R S  #################################

    if [has_users]
    then
        ask "Ajouter les utilisateurs manquants ?" "Y" "add_users" ""
    fi

    ###################################  M O D U L E S  ###############################

    if [has_modules]
    then
        ask "Installer les modules SeLinux ?" "Y" "install_modules" ""
    fi

    #################################  S E R V I C E S ################################

    if [has_services]
    then
        ask "Activer et demarrer les services ?" "Y" "restart_services" ""
    fi

    ##################################  N E T W O R K  ################################

    ask "Configurer les parametres reseaux ?" "Y" "configure_networks" ""

    #####################################  G U I  ###################################

    if [has_a_gui]
    then
        ask "Activer l'interface graphique ?" "Y" "enable_gui" ""
    fi

    #################################  F I R E W A L L ################################

    ask "Configurer le pare-feu ?" "Y" "configure_firewall" ""

    #########################  A C T I V E   D I R E C T O R Y ########################

    if [server_has_ad]
    then
        ask "Rejoindre le domaine ?" "Y" "join_domain" ""
    fi

    ####################################  S N M P #####################################

    if [server_has_snmp]
    then
        ask "Configurer les remontees SNMP ?" "Y" "configure_snmp" ""
    fi     

    ##################################  S A M B A  ###################################

    if [is_a_samba_server]
    then
        ask "Configurer le serveur SAMBA ?" "Y" "configure_samba" ""
    fi

    #################################  Z A B B I X  ###################################

    if [is_a_zabbix_server]
    then
        ask "Configurer le serveur Zabbix ?" "Y" "configure_zabbix" ""
    fi

    #################################  V E E A M  ####################################

    if [is_a_veeam_client]
    then
        ask "Configurer le serveur VEEAM ?" "Y" "configure_veeam" ""
    fi  

    ######################################  P A M  ####################################

    ask "Mettre a jour la configuration PAM ?" "Y" "update_pam" ""

    ######################################  N F S  ####################################

    if [has_nfs]
    then
        ask "Configurer le serveur NFS ?" "Y" "configure_nfs" ""
    fi

    ######################################  X C A  ####################################

    if [has_xca]
    then
        ask "Installer XCA ?" "Y" "install_xca" ""
    fi

    ###############################  S C P   B A C K U P  #############################

    if [has_scp_backup]
    then
        ask "Configurer les sauvegardes SCP ?" "Y" "configure_scp_backups" ""
    fi

    ########################  S C P   B A C K U P  S E R V E R  #######################

    if [is_scp_backup_server]
    then
        ask "Configurer les dossiers de sauvegardes SCP ?" "Y" "configure_scp_backups_folders" ""
    fi

    #####################################  V M R C  ###################################

    if [has_vmrc]
    then
        ask "Installer VMRC ?" "Y" "install_vmrc" ""
    fi

    ######################################  S S H  ####################################

    if [has_ssh_keys]
    then
        ask "Appliquer les permissions sur les clés SSH ?" "Y" "update_ssh_keys" ""
    fi

    #################################  S E R V I C E S ################################

    if [has_services]
    then
        ask "Redemarrer les services ?" "Y" "restart_services" ""
    fi

    #####################################  E N D  #####################################

    title "I N S T A L L A T I O N   T E R M I N E E"
}

# Récupère le nom du script (myfile.sh)
script_file=${0##*/}
# Crée le nom du fichier de log (myfile.sh -> myfile.log)
log_file=${script_file/sh/log}

# 
# stdin (0) est redirigé vers stdout (1)
# stderr (2) est redirigé vers stdout (1)
# stdout (+stderr +stdin) est dupliqué vers $log_file
#
main 2>&1 | tee $log_file

echo -e "Tout le detail de l'installation est retranscrit dans le fichier $log_file.\n"

ask "L'installation est terminee. Voulez-vous redemarrer le systeme (recommandé) ?" "Y" "reboot" ""