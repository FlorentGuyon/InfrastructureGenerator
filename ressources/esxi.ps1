$PSDefaultParameterValues["*:Encoding"] = "utf8"

#
#   Affiche une question
#
function Ask_Question ($title, $question, $delay, $default_answer, $action) {
   
    #
    #   Answer id:
    #
    #     -1: Timeout
    #      1: OK button
    #      2: Cancel button
    #      3: Abort button
    #      4: Retry button
    #      5: Ignore button
    #      6: Yes button
    #      7: No button
    #
    if ($default_answer -eq "y") {
        
        $default_answer_id = 6
    
    } else {
        
        $default_answer_id = 7
    }

    $sh = New-Object -ComObject "Wscript.Shell"

    #
    #   Buttons :
    #
    #      0: OK button.
    #      1: OK and Cancel buttons.
    #      2: Abort, Retry, and Ignore buttons.
    #      3: Yes, No, and Cancel buttons.
    #      4: Yes and No buttons.
    #      5: Retry and Cancel buttons.
    #
    #   Icon:
    #
    #      16: "Stop Mark" icon.
    #      32: "Question Mark" icon.
    #      48: "Exclamation Mark" icon.
    #      64: "Information Mark" icon. 
    #
    $answer_id = $sh.Popup($question, $delay, $title, 4+32)

    # Timeout
    if ($answer_id -eq -1) {

        $answer_id = $default_answer_id
    }

    # Yes
    if ($answer_id -eq 6) {

        Invoke-Expression $action
    }
}

#
#    Affiche un titre
#
function Print_Title ($title, $color) {

    #
    # Cree un titre encadre
    #
    $frame = "`n"
    $frame += " ####" + ("#" * $title.Length) + "####`n"
    $frame += " #   " + (" " * $title.Length) + "   #`n"
    $frame += " #   " + $title                + "   #`n"
    $frame += " #   " + (" " * $title.Length) + "   #`n"
    $frame += " ####" + ("#" * $title.Length) + "####`n"

    #
    # Affiche le titre encadre
    #
    Write-Host $frame -ForegroundColor $color
}

#
#    Quitte le programme en erreur
#
function Fatal_Error($text) {

    #
    # Affiche un message d'erreur
    #
    Write-Host $text --ForegroundColor "Red"

    #
    # Quitte le programme
    #
    exit
}

#
#    Connexion au virtualisateur
#
Function Connect_Esxi {

    #
    # Connexion au virtualisateur
    #
    Connect-VIServer -Server "[esxi_ip]" -User "[esx_admin_id]" -Password "[esx_admin_mdp]" -Verbose

    #
    # Enregistrement du virtualisateur
    #
    $global:VMware_Esxi = Get-VMHost "[esxi_ip]" -Verbose

    #
    # Enregistrement de la console client du virtualisateur
    #
    $global:Esxi_Cli = Get-EsxCli -vmhost $global:VMware_Esxi -V2 -Verbose
}

#
#    Mise-a-jour du nom d'hôte 
#
Function Update_Hostname {

    #
    # Affichage du nom d'hote
    #
    Write-Host $global:Esxi_Cli.system.hostname.get.Invoke()

    #
    # Mise-a-jour du nom d'hôte
    # Source: https://www.virten.net/2014/02/howto-use-esxcli-in-powercli/
    #
    $global:Esxi_Cli.system.hostname.set.Invoke(@{host="[esxi_hostname]"; domain="[esxi_domain]"})

    #
    # Affichage du nouveau nom d'hote
    #
    Write-Host $global:Esxi_Cli.system.hostname.get.Invoke()
}

#
#    Joiture a un domaine
#
Function Join_Domain {
    
    #
    # Definir le mode d'authentification en centralise via un domaine.
    #
    $global:VMware_Esxi | Get-VMHostAuthentication | Set-VMHostAuthentication -JoinDomain -Domain "[esxi_domain]" -user "[esx_jonction_domaine_user]" -password "[esx_jonction_domaine_password]"

    #
    # Configuration du groupe AD possedant des privileges administrateurs.
    # Source: https://developer.vmware.com/docs/5730/cmdlet-reference/doc/Set-VMHostAuthentication.html?h=Set-VMHostAuthentication# https://developer.vmware.com/docs/5730/cmdlet-reference/doc/Set-AdvancedSetting.html
    #
    $admin_group_list = @([admin_group_list])

    Foreach ($admin_group in $admin_group_list) {
        New-VIPermission -Entity $global:VMware_Esxi -Principal $admin_group -Role "Admin" -Propagate $true
    }

    #
    # Ajout d'un domaine de recherche
    # Source: https://www.virten.net/2014/02/howto-use-esxcli-in-powercli/
    #
    $global:Esxi_Cli.network.ip.dns.search.add.Invoke(@{domain="[esxi_domain]"})

    #
    # Affichage de la liste des domaines de recherche
    #
    Write-Host $global:Esxi_Cli.network.ip.dns.search.list.Invoke()
}

#
#    Activation de la licence
#
Function Activate_Licence {
    
    #
    # Configurer la cle de licence
    # Source: https://developer.vmware.com/docs/5730/cmdlet-reference/doc/Set-VMHost.html
    #
    Set-VMHost -VMHost $global:VMware_Esxi -LicenseKey "[esx_licence_key]"
} 

#
#    Desactivation de services (Uniquement pour vCenter?)
#
Function Set_SSL_Certificat {

    $CACertificate = Get-Content ".\certificates\[ca_certificate]" -Raw
    $ServerCertificate = Get-Content ".\certificates\[server_certificate]" -Raw
    $ServerPrivateKey = Get-Content ".\private_keys\[server_private_key]" -Raw

    #
    # Activation du SSH
    #
    $global:VMware_Esxi | Get-VMHostService | where { $_.key -eq "TSM-SSH" } | Start-VMHostService -Confirm:$false


    #
    # Copie des certificats
    #
    scp ".\certificates\[ca_certificate]" ".\certificates\[server_certificate]" ".\private_keys\[server_private_key]" root@[esxi_ip]:/etc/vmware/ssl/

    
    #
    # Application des certificats
    #
    ssh root@[esxi_ip] "cat /etc/vmware/ssl/[ca_certificate] >> /etc/vmware/ssl/castore.pem && cat /etc/vmware/ssl/[server_certificate] > /etc/vmware/ssl/rui.crt && cat /etc/vmware/ssl/[server_private_key] > /etc/vmware/ssl/rui.key"
}

#
#    Desactivation de services
#
Function Disable_Services {

    #
    # Liste des services a desactiver
    #
    $Services = @([esx_services_desactives])

    #
    # Pour chaque service de la liste
    #
    foreach ($Service in $Services) {

        #
        # Desactiver le service
        # Source: https://developer.vmware.com/docs/5730/cmdlet-reference/doc/Set-VMHostService.html# https://vdc-repo.vmware.com/vmwb-repository/dcr-public/f2319b2a-6378-4635-a1cd-90b14949b62a/0ac4f829-f79b-40a6-ac10-d22ec76937ec/doc/Stop-VMHostService.html
        #
        $global:VMware_Esxi | Get-VMHostService | where { $_.key -eq "$service" } | Set-VMHostService -Policy "Off" | Stop-VMHostService -Confirm:$false
    }

    #
    # Affichage de la liste des services
    #
    $global:VMware_Esxi | Get-VMHostService
}

#
#    Configuration du service de remonte de logs
#
Function Configure_Syslog_Service {

    #
    # Activation du SSH
    #
    $global:VMware_Esxi | Get-VMHostService | where { $_.key -eq "TSM-SSH" } | Start-VMHostService -Confirm:$false
    
    #
    # Transfert des certificats
    #
    scp ./certificates/[ca_certificate] ./certificates/[root_certificate] root@[esxi_ip]:/etc/vmware/ssl/

    $arguments = $global:Esxi_Cli.system.security.certificatestore.add.CreateArgs()
   
    $arguments.filename = "/etc/vmware/ssl/[ca_certificate]" 
    
    try {

        $global:Esxi_Cli.system.security.certificatestore.add.Invoke($arguments)
    
    } catch {

        Write-Host "Certificat déjà présent"
    }

    $arguments.filename = "/etc/vmware/ssl/[root_certificate]"
    
    try {

        $global:Esxi_Cli.system.security.certificatestore.add.Invoke($arguments)
    
    } catch {

        Write-Host "Certificat déjà présent"
    }

    #
    # Transfert de la nouvelle règle de pare-feu
    #
    scp ./custom-service.xml root@[esxi_ip]:/etc/vmware/firewall/
    
    #
    # Desactivation du SSH
    #
    $global:VMware_Esxi | Get-VMHostService | where { $_.key -eq "TSM-SSH" } | Stop-VMHostService -Confirm:$false

    #
    # Ajout d'une regle de pare-feu autorisant le flux syslog. 
    # Source: https://kb.vmware.com/s/article/2008226
    $global:VMware_Esxi | Get-VMHostFirewallException -Name "syslog" | Set-VMHostFirewallException -Enabled $false
    $global:VMware_Esxi | Get-VMHostFirewallException -Name "syslog-over-tls" | Set-VMHostFirewallException -Enabled $true

    #
    # Redemarrage du service firewall
    #
    $global:Esxi_Cli.network.firewall.refresh.invoke()

    #
    # Configurer le serveur de remontes de logs
    #
    $arguments = $global:Esxi_Cli.system.syslog.config.set.CreateArgs()

    $arguments.loghost = "ssl://[esx_service_syslog_serveur]:[esx_service_syslog_port]"
    $arguments.checksslcerts = $true
    $arguments.x509strict = $false
    $arguments.logdir = "/scratch/log"
    $arguments.queuedropmark = 90
    $arguments.logdirunique = $false
    $arguments.defaultrotate = 8
    $arguments.droplogrotate = 10
    $arguments.defaultsize = 1024
    $arguments.droplogsize = 100
    $arguments.defaulttimeout = 180
    $arguments.crlcheck = $false

    $global:Esxi_Cli.system.syslog.config.set.Invoke($arguments)

    #
    # Redemarrage du service syslog
    #
    $global:Esxi_Cli.system.syslog.reload.invoke()
}

#
#    Configuration du service SNMP
#
Function Configure_SNMP_Service {

    #
    # Parametres complets
    #
    $arguments = $global:Esxi_Cli.system.snmp.set.CreateArgs()

    $arguments.enable = $true
    $arguments.loglevel = "warning"
    $arguments.authentication = "[esx_service_snmp_hash_auth_algo]"
    $arguments.privacy = "[esx_service_snmp_hash_priv_algo]"
    $arguments.port = "[esx_service_snmp_port]"
    $arguments.engineid = -join ((0..9) | Get-Random -Count 10)

    #
    # Configuration du service SNMP
    #
    $global:Esxi_Cli.system.snmp.set.Invoke($arguments)


    $arguments = $global:Esxi_Cli.system.snmp.hash.CreateArgs()

    $arguments.authhash = "[esx_service_snmp_hash_auth]"
    $arguments.privhash = "[esx_service_snmp_hash_priv]"
    $arguments.rawsecret = $true

    #
    # Generer une empreinte des mots de passe de l'utilisateur SNMP
    # Retour:
    #  Authhash: 2d991687b1678d44de425096570262b61b90d50d
    #  Privhash: 2d991687b1678d44de425096570262b61b90d50d
    $hash = $global:Esxi_Cli.system.snmp.hash.Invoke($arguments)

    $AuthHash = $hash.AuthHash
    $PrivHash = $hash.PrivHash
    
    #
    # Creation de l'utilisateur SNMP
    #
    $SNMP_User = "[esx_service_snmp_utilisateur_snmp]/$AuthHash/$PrivHash/priv"

    #
    # Former la cible SNMPv3.
    # 
    $SNMP_Target = "[esx_service_snmp_cible_SNMP]/[esx_service_snmp_utilisateur_snmp]/priv/trap"

    #
    # Parametres complets
    #
    $arguments = $global:Esxi_Cli.system.snmp.set.CreateArgs()

    $arguments.users = $SNMP_User
    $arguments.v3targets = $SNMP_Target

    #
    # Configuration du service SNMP
    #
    $global:Esxi_Cli.system.snmp.set.Invoke($arguments)


    #
    # Afficher la configuration post-modification.
    #
    $global:Esxi_Cli.system.snmp.get.Invoke()
 }  

#
#    Configuration du service de synchronisation horaire
#
Function Configure_NTP_Service {

    #
    # Verifier la configuration NTP actuelle.
    # Source: https://kb.vmware.com/s/article/2008226
    #
	Get-VMHost | Sort-Object Name | Select-Object Name, @{N="Cluster";E={$_ | Get-Cluster}}, @{N="Datacenter";E={$_ | Get-Datacenter}}, @{N="NTPServiceRunning";E={($_ | ``Get-VmHostService | Where-Object {$_.key-eq "ntpd"}).Running}}, @{N="StartupPolicy";E={($_ | Get-VmHostService | Where-Object {$_.key-eq "ntpd"}).Policy}}, @{N="NTPServers";E={$_ | ``Get-VMHostNtpServer}}, @{N="Date&Time";E={(get-view $_.ExtensionData.configManager.DateTimeSystem).QueryDateTime()}} | format-table -autosize
    
    #
    # Arret temporaire du service NTP
    #
    Get-VMHost | Get-VmHostService | Where-Object {$_.key -eq "ntpd"} | Stop-VMHostService -Confirm:$false

    #
    # Configuration du service NTP en mode automatique
    #
    Get-VMHost | Get-VmHostService | Where-Object {$_.key -eq "ntpd"} | Set-VMHostService -policy "automatic"

    #
    # Configuration du serveur NTP
    #
    Get-VMHost | Add-VMHostNtpServer -NtpServer [esx_network_ntp]; Get-VMHost 
    
    #
    # Demarrage du service NTP
    #
    Get-VMHost | Get-VmHostService | Where-Object {$_.key -eq "ntpd"} | Start-VMHostService
}

#
#    Configuration de l'expiration des sessions
#
Function Set_Sessions_Settings {

    #
    # Expiration des sessions "Direct Console User Interface".
    # Source: https://developer.vmware.com/docs/5730/cmdlet-reference/doc/Set-AdvancedSetting.html
    #
    Get-AdvancedSetting -Entity (Get-VMHost) -Name "UserVars.DcuiTimeOut" | Set-AdvancedSetting -Value "[esx_expiration_sessions_dcui]" -Confirm:$false
    
    #
    # Expiration des sessions SSH.
    # Source: https://developer.vmware.com/docs/5730/cmdlet-reference/doc/Set-AdvancedSetting.html
    #
    Get-AdvancedSetting -Entity (Get-VMHost) -Name "UserVars.ESXiShellTimeOut" | Set-AdvancedSetting -Value "[esx_expiration_sessions_shell]" -Confirm:$false 

    #
    # Expiration des sessions Web.
    # Source: https://developer.vmware.com/docs/5730/cmdlet-reference/doc/Set-AdvancedSetting.html
    #
    Get-AdvancedSetting -Entity (Get-VMHost) -Name "UserVars.HostClientSessionTimeout" | Set-AdvancedSetting -Value "[esx_expiration_sessions_web]" -Confirm:$false
}

#
#    Renommage de la base de donnees
#
Function Rename_Datastore {

    #    
    # Source: https://vdc-repo.vmware.com/vmwb-repository/dcr-public/64ee9c63-6647-46bd-8685-32b97590c294/b5861550-655c-4498-ba7e-8b24b492bf31/doc/Set-Datastore.html
    #
    Set-Datastore "[esx_datastore_old_name]" -Name "[esx_datastore_new_name]"
}

#
#    Creation de commutateurs virtuels
#
Function New_Virtual_Switches {

    #
    # Source: https://vdc-repo.vmware.com/vmwb-repository/dcr-public/6fb85470-f6ca-4341-858d-12ffd94d975e/4bee17f3-579b-474e-b51c-898e38cc0abb/doc/New-VirtualSwitch.html
    #
    [esx_vswitchs]
}

#
#    Creation de groupes de ports virtuels
#
Function New_Port_Groups {

    #
    # https://developer.vmware.com/docs/powercli/latest/vmware.vimautomation.core/commands/new-virtualportgroup/#Default
    #
    [esx_portgroups]
}

#
#    Creation de machines virtuelles
#
Function Copie_ISO {

    #
    # Telechargement des fichiers ISO
    #
    $datastore = Get-Datastore "[esx_datastore_new_name]"
    New-PSDrive -Location $datastore -Name "iso" -PSProvider "VimDatastore" -Root "\"
    [esx_iso]

}

Function Set_Start_Policy {

    $global:VMware_Esxi | Get-VMHostStartPolicy | Set-VMHostStartPolicy -Enabled:$true -StartDelay 0 -StopAction "PowerOff" -StopDelay 0 -WaitForHeartBeat:$true    
}

Function New_Virtual_Machines {
    #
    # Source: https://docs.vmware.com/en/VMware-HCX/4.3/hcx-user-guide/GUID-D4FFCBD6-9FEC-44E5-9E26-1BD0A2A81389.html
    # guest_id : dosGuest, win31Guest, win95Guest, win98Guest, winMeGuest, winNTGuest, win2000ProGuest, win2000ServGuest, win2000AdvServGuest, winXPHomeGuest, winXPProGuest, winXPPro64Guest, winNetWebGuest, winNetStandardGuest, winNetEnterpriseGuest, winNetDatacenterGuest, winNetBusinessGuest, winNetStandard64Guest, winNetEnterprise64Guest, winLonghornGuest, winLonghorn64Guest, winNetDatacenter64Guest, winVistaGuest, winVista64Guest, windows7Guest, windows7_64Guest, windows7Server64Guest, windows8Guest, windows8_64Guest, windows8Server64Guest, windows9Guest, windows9_64Guest, windows9Server64Guest, windowsHyperVGuest, windows2019srv_64Guest, windows2019srvNext_64Guest, freebsdGuest, freebsd64Guest, freebsd11Guest, freebsd11_64Guest, freebsd12Guest, freebsd12_64Guest, freebsd13Guest, freebsd13_64Guest, redhatGuest, rhel2Guest, rhel3Guest, rhel3_64Guest, rhel4Guest, rhel4_64Guest, rhel5Guest, rhel5_64Guest, rhel6Guest, rhel6_64Guest, rhel7Guest, rhel7_64Guest, rhel8_64Guest, rhel9_64Guest, centosGuest, centos64Guest, centos6Guest, centos6_64Guest, centos7Guest, centos7_64Guest, centos8_64Guest, centos9_64Guest, oracleLinuxGuest, oracleLinux64Guest, oracleLinux6Guest, oracleLinux6_64Guest, oracleLinux7Guest, oracleLinux7_64Guest, oracleLinux8_64Guest, oracleLinux9_64Guest, suseGuest, suse64Guest, slesGuest, sles64Guest, sles10Guest, sles10_64Guest, sles11Guest, sles11_64Guest, sles12Guest, sles12_64Guest, sles15_64Guest, sles16_64Guest, nld9Guest, oesGuest, sjdsGuest, mandrakeGuest, mandrivaGuest,mandriva64Guest, turboLinuxGuest, turboLinux64Guest, ubuntuGuest, ubuntu64Guest, debian4Guest, debian4_64Guest, debian5Guest, debian5_64Guest, debian6Guest, debian6_64Guest, debian7Guest, debian7_64Guest, debian8Guest, debian8_64Guest, debian9Guest, debian9_64Guest, debian10Guest, debian10_64Guest, debian11Guest, debian11_64Guest, asianux3Guest, asianux3_64Guest, asianux4Guest, asianux4_64Guest, asianux5_64Guest, asianux7_64Guest, asianux8_64Guest, asianux9_64Guest, opensuseGuest, opensuse64Guest, fedoraGuest, fedora64Guest, coreos64Guest, vmwarePhoton64Guest, other24xLinuxGuest, other26xLinuxGuest, otherLinuxGuest, other3xLinuxGuest, other4xLinuxGuest, other5xLinuxGuest, genericLinuxGuest, other24xLinux64Guest, other26xLinux64Guest, other3xLinux64Guest, other4xLinux64Guest, other5xLinux64Guest, otherLinux64Guest, solaris6Guest, solaris7Guest, solaris8Guest, solaris9Guest, solaris10Guest, solaris10_64Guest, solaris11_64Guest, os2Guest, eComStationGuest, eComStation2Guest, netware4Guest, netware5Guest, netware6Guest, openServer5Guest, openServer6Guest, unixWare7Guest, darwinGuest, darwin64Guest, darwin10Guest, darwin10_64Guest, darwin11Guest, darwin11_64Guest, darwin12_64Guest, darwin13_64Guest, darwin14_64Guest, darwin15_64Guest, darwin16_64Guest, darwin17_64Guest, darwin18_64Guest, darwin19_64Guest, darwin20_64Guest, darwin21_64Guest, vmkernelGuest, vmkernel5Guest, vmkernel6Guest, vmkernel65Guest, vmkernel7Guest, amazonlinux2_64Guest, amazonlinux3_64Guest, crxPod1Guest, otherGuest, otherGuest64
    #
    [esx_vms]
}

Function MAC_config {
    #
    # Source: https://docs.vmware.com/en/VMware-HCX/4.3/hcx-user-guide/GUID-D4FFCBD6-9FEC-44E5-9E26-1BD0A2A81389.html
    # guest_id : dosGuest, win31Guest, win95Guest, win98Guest, winMeGuest, winNTGuest, win2000ProGuest, win2000ServGuest, win2000AdvServGuest, winXPHomeGuest, winXPProGuest, winXPPro64Guest, winNetWebGuest, winNetStandardGuest, winNetEnterpriseGuest, winNetDatacenterGuest, winNetBusinessGuest, winNetStandard64Guest, winNetEnterprise64Guest, winLonghornGuest, winLonghorn64Guest, winNetDatacenter64Guest, winVistaGuest, winVista64Guest, windows7Guest, windows7_64Guest, windows7Server64Guest, windows8Guest, windows8_64Guest, windows8Server64Guest, windows9Guest, windows9_64Guest, windows9Server64Guest, windowsHyperVGuest, windows2019srv_64Guest, windows2019srvNext_64Guest, freebsdGuest, freebsd64Guest, freebsd11Guest, freebsd11_64Guest, freebsd12Guest, freebsd12_64Guest, freebsd13Guest, freebsd13_64Guest, redhatGuest, rhel2Guest, rhel3Guest, rhel3_64Guest, rhel4Guest, rhel4_64Guest, rhel5Guest, rhel5_64Guest, rhel6Guest, rhel6_64Guest, rhel7Guest, rhel7_64Guest, rhel8_64Guest, rhel9_64Guest, centosGuest, centos64Guest, centos6Guest, centos6_64Guest, centos7Guest, centos7_64Guest, centos8_64Guest, centos9_64Guest, oracleLinuxGuest, oracleLinux64Guest, oracleLinux6Guest, oracleLinux6_64Guest, oracleLinux7Guest, oracleLinux7_64Guest, oracleLinux8_64Guest, oracleLinux9_64Guest, suseGuest, suse64Guest, slesGuest, sles64Guest, sles10Guest, sles10_64Guest, sles11Guest, sles11_64Guest, sles12Guest, sles12_64Guest, sles15_64Guest, sles16_64Guest, nld9Guest, oesGuest, sjdsGuest, mandrakeGuest, mandrivaGuest,mandriva64Guest, turboLinuxGuest, turboLinux64Guest, ubuntuGuest, ubuntu64Guest, debian4Guest, debian4_64Guest, debian5Guest, debian5_64Guest, debian6Guest, debian6_64Guest, debian7Guest, debian7_64Guest, debian8Guest, debian8_64Guest, debian9Guest, debian9_64Guest, debian10Guest, debian10_64Guest, debian11Guest, debian11_64Guest, asianux3Guest, asianux3_64Guest, asianux4Guest, asianux4_64Guest, asianux5_64Guest, asianux7_64Guest, asianux8_64Guest, asianux9_64Guest, opensuseGuest, opensuse64Guest, fedoraGuest, fedora64Guest, coreos64Guest, vmwarePhoton64Guest, other24xLinuxGuest, other26xLinuxGuest, otherLinuxGuest, other3xLinuxGuest, other4xLinuxGuest, other5xLinuxGuest, genericLinuxGuest, other24xLinux64Guest, other26xLinux64Guest, other3xLinux64Guest, other4xLinux64Guest, other5xLinux64Guest, otherLinux64Guest, solaris6Guest, solaris7Guest, solaris8Guest, solaris9Guest, solaris10Guest, solaris10_64Guest, solaris11_64Guest, os2Guest, eComStationGuest, eComStation2Guest, netware4Guest, netware5Guest, netware6Guest, openServer5Guest, openServer6Guest, unixWare7Guest, darwinGuest, darwin64Guest, darwin10Guest, darwin10_64Guest, darwin11Guest, darwin11_64Guest, darwin12_64Guest, darwin13_64Guest, darwin14_64Guest, darwin15_64Guest, darwin16_64Guest, darwin17_64Guest, darwin18_64Guest, darwin19_64Guest, darwin20_64Guest, darwin21_64Guest, vmkernelGuest, vmkernel5Guest, vmkernel6Guest, vmkernel65Guest, vmkernel7Guest, amazonlinux2_64Guest, amazonlinux3_64Guest, crxPod1Guest, otherGuest, otherGuest64
    #
    [esx_mac]
}

#
#    Redemarrage du virtualisateur
#
Function Reboot_ESXI {
 
    #
    # Source: https://vdc-repo.vmware.com/vmwb-repository/dcr-public/0a01c8b1-4515-46e5-ade9-d457877d167e/f63b3243-b9c0-4199-bfc9-8a6b3b11151a/doc/Restart-VMHost.html
    #
    Restart-VMHost [esxi_ip] -Force
}

#<------------------------- Fonction - Introduction au script   ------------------------->#
Function Main {

    Clear-Host

    Write-Host "  __  __ ___ ___  ____   "
    Write-Host " |  \/  |_ _/ _ \/ ___|  "
    Write-Host " | |\/| || | | | \___ \  "
    Write-Host " | |  | || | |_| |___) | "
    Write-Host " |_|  |_|___\___/|____/  "

    Print_Title -title "Configuration du virtualisateur [esxi_hostname]" -color "Cyan"
    
    #
    # Ajoute le dossier contenant les modules PowerCLI dans la variable d'environnement afin qu'ils soient accessibles par PowerShell
    #
    Write-Host "Importation du module VMware.PowerCLI."
    $disk_letter = (Resolve-Path ".").ToString().Substring(0,2)
    $module_path = "$disk_letter\MODULES\VMware-PowerCLI"
    $env:PSModulePath=$module_path

    #
    # Ignorer le fait que l'ESXI possede un certificat auto-signe.
    #
    Write-Host "Autoriser les connexions non securisees vers le virtualisateur."
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -ParticipateInCEIP $false

    if (Connect_Esxi) {

        $steps = @(
            @{question = "Mise-a-jour du certificat SSL"; action = "Set_SSL_Certificat"}
            @{question = "Mise-a-jour du nom d'hôte"; action = "Update_Hostname"},
            @{question = "Jointure au domaine"; action = "Join_Domain"},
            @{question = "Attribution de la cle de licence ?"; action = "Activate_Licence"},
            @{question = "Desactivation des services non-utilises"; action = "Disable_Services"},
            @{question = "Configurer des remontes de logs"; action = "Configure_Syslog_Service"},
            @{question = "Configuration de la surveillance"; action = "Configure_SNMP_Service"},
            @{question = "Configuration de la synchronisation horaire"; action = "Configure_NTP_Service"},
            @{question = "Configuration de la duree d'inactivitee des sessions"; action = "Set_Sessions_Settings"},
            @{question = "Mise-a-jour du nom de la base de donnees"; action = "Rename_Datastore"},
            @{question = "Creation des commutateurs virtuels"; action = "New_Virtual_Switches"},
            @{question = "Creation des groupes de ports virtuels"; action = "New_Port_Groups"},
            @{question = "Copie des ISO"; action = "Copie_ISO"},
            @{question = "Mise-a-jour de la politique de redemarrage"; action = "Set_Start_Policy"},
            @{question = "Creation des machines virtuelles"; action = "New_Virtual_Machines"},
            @{question = "Forcing des adresse MAC VM"; action = "MAC_config"},
            @{question = "Redemarrage du virtualisateur"; action = "Reboot_ESXI"}
        )
     
        Foreach ($step in $steps) { 

            Ask_Question -title "Configuration du virtualisateur [esxi_hostname]" -question $($step.question) -action $($step.action) -delay 10 -default_answer "y"
        }

        Print_Title -title "La configuration du virtualisateur [esxi_hostname] est terminee." -color "Cyan"

    } else {

        Write-Host "La connexion au virtualisateur a echouee. Verifier les parametres de connexion."
        exit
    }
}

Main