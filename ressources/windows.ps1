$PSDefaultParameterValues["*:Encoding"] = "utf8"

#
#   Show a box with a question and buttons to answer
#
#   Parameters:
#       
#       $title: Text to print on top of the box, string
#       $question:  Text to print in the middle ot the box, string
#       $delay: Number of seconds to wait before canceling the question, integer (0: unlimited)
#       $default_answer: Answer to choose if the deadline is exceeded, string ("y" or "n")
#       $action: command to execute if the answer is "yes"
#
#   Exemple:
#
#       ########################################################
#       # Installation complete                                # 
#       #   __                                                 # 
#       #  |  /                                                #
#       #    /   Do you want to shutdown the computer ? (Y/n)  #
#       #    |                                                 # 
#       #    .           #######      #######                  #
#       #                # Yes #      # No  #                  #
#       #                #######      #######                  #
#       ########################################################
#

function ask ($title, $question, $delay, $default_answer, $action) {
   
    #
    #   Answer id:
    #
    #      -1: Timeout
    #       1: OK button
    #       2: Cancel button
    #       3: Abort button
    #       4: Retry button
    #       5: Ignore button
    #       6: Yes button
    #       7: No button
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
    #       0: OK button.
    #       1: OK and Cancel buttons.
    #       2: Abort, Retry, and Ignore buttons.
    #       3: Yes, No, and Cancel buttons.
    #       4: Yes and No buttons.
    #       5: Retry and Cancel buttons.
    #
    #   Icon:
    #
    #       16: "Stop Mark" icon.
    #       32: "Question Mark" icon.
    #       48: "Exclamation Mark" icon.
    #       64: "Information Mark" icon. 
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
#   Print a framed sentence with a specific color in the standard output
#
#   Parameters:
#
#       $title: Sentence to show, string
#       $color: Foreground color, string (Black, DarkBlue, DarkGreen, DarkCyan, DarkRed, DarkMagenta, DarkYellow, Gray, DarkGray, Blue, Green, Cyan, Red, Magenta, Yellow, White)
#
#   Exemple:
#
#       #############
#       # Welcome ! #
#       #############
#

function Print-Title ($title, $color) {

    $frame = "`n"
    $frame += "    ####" + ("#" * $title.Length) + "####`n"
    $frame += "    #   " + (" " * $title.Length) + "   #`n"
    $frame += "    #   " + $title                + "   #`n"
    $frame += "    #   " + (" " * $title.Length) + "   #`n"
    $frame += "    ####" + ("#" * $title.Length) + "####`n"

    Write-Host $frame -ForegroundColor $color
}


function fatal_error($text) {

    Write-Host $text --ForegroundColor "Red"
    exit
}

function update_tree () {

    Copy-Item -Recurse -Force -Verbose ".\tree\*" "C:\"
}

function install_driver ($driver) {

    Print-Title -title "Installation du driver $driver" -color "Cyan"

    $disk_letter = (Resolve-Path ".").ToString().Substring(0,2)
    $driver_path = "$disk_letter\PILOTES\$driver"
    (Start-Process $driver_path -PassThru).WaitForExit()
}

function install_certificates () {

    Print-Title -title "Installation des certificats" -color "Cyan"

    $certificates = @([certificates])

    Foreach ($certificate in $certificates) {

        $file_path = $certificate.file_path
        $cert_store_location = $certificate.cert_store_location

        Import-Certificate -FilePath $file_path -CertStoreLocation $cert_store_location
    }
}

function update_event_logs () {

    [event_log]
}


#
#   Rename and setup a network interface
#
#   Parameters:
#
#       $current_interface_name: Default name of the network interface, string (Ethernet0)
#       $new_interface_name: New name for the network interface, string (NET_ADMIN)
#       $interface_ipv4_address: New IPv4 address for the network interface, string (212.29.0.1)
#       $subnetwork_mask: New Sub-network mask for the network interface, string (24)
#

function setup_network_interface ($current_interface_name, $new_interface_name, $interface_ipv4_address, $subnetwork_mask) {

    Print-Title -title "Configuration de l'interface réseau $new_interface_name" -color "Cyan"

    $NetAdapters = Get-NetAdapter

    if ($NetAdapters.name -contains $new_interface_name) {

        Write-Host "L'interface $new_interface_name existe déjà." -ForegroundColor "Cyan"
    
    } else {

        if ($NetAdapters.name -contains $current_interface_name) {

            Rename-NetAdapter -Name $current_interface_name -NewName $new_interface_name -Confirm:$false
            Write-Host "L'interface $interface_name ($interface_id) a été renomée $new_interface_name" -ForegroundColor "Green"

        } else {

            Write-Host "L'interface $current_interface_name n'existe pas." -ForegroundColor "Red"
            return
        }

    }

    $NetAdapter = Get-NetAdapter -Name $new_interface_name

    #Disable-NetAdapterBinding -InterfaceAlias $NetAdapter.ifIndex -ComponentID ms_tcpip6
    #Write-Host "L'IPv6 a été désactivé sur l'interface $new_interface_name." -ForegroundColor "Green"

    # On supprime la configuration actuelle de l'interface réseau :
    Remove-NetIPAddress -InterfaceIndex $NetAdapter.ifIndex -Confirm:$false
    Write-Host "L'ancienne configuration réseau de l'interface $new_interface_name a été supprimée." -ForegroundColor "Green"
    
    # On désactive l'IPv6 :
    Disable-NetAdapterBinding -Name $NetAdapter.Name -ComponentID "ms_tcpip6"
    Write-Host "IPv6 désactivé." -ForegroundColor "Green" 
           
    # On applique la nouvelle configuration :
    Set-NetIPInterface -InterfaceIndex $NetAdapter.ifIndex -AddressFamily "IPv4" -Dhcp "Disabled"
    New-NetIPAddress -InterfaceIndex $NetAdapter.ifIndex -AddressFamily "IPv4" -IPAddress $interface_ipv4_address -PrefixLength $subnetwork_mask
    Write-Host "L'interface $new_interface_name a été reconfigurée." -ForegroundColor "Green" 

}

#
#   Remove the IPv4 adress of the DNS server of the network interface of administration 
#   and add one for the network interface of infrastructure
#
#   Parameters:
#   
#       $admin_interface_name: New name of the network interface of administration, string (NET_ADMIN)
#       $infra_interface_name: New name of the network interface of infrastructure, string (NET_INFRA)
#

function setup_dns_client ($interface_name, $dns) {

    Print-Title -title "Configuration du server DNS" -color "Cyan"

    Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter -Name $interface_name).ifIndex -ServerAddresses $dns
    Write-Host "Le serveur DNS de l'interface $infra_interface_name a été configuré." -ForegroundColor "Green"
}

#
#   Ajoute les nouvelles routes statiques
#

function setup_static_routes {

    Print-Title -title "Configuration des routes statiques" -color "Cyan"

    # On ajoute les nouvelles routes statiques
    [routes]
        
    Write-Host "Les routes statiques ont été configurées." -ForegroundColor "Green"
}

#
#   Update the hostname of the computer and join the computer to the Active Directory server
#

function join_domain {
    
    Print-Title -title "Accostage au serveur Active Directory" -color "Cyan"
    
    #On récupère le hostname de la machine actuelle
    $current_hostname = Hostname

    #On récupère le domaine actuel
    $current_domain_name = (Get-WmiObject win32_computersystem).Domain

    #Check si le domaine est à la cible            
    if ($current_domain_name -eq "[domain]") {

        Write-Host "[hostname] est déjà accosté au domaine [domain] " -ForegroundColor "Blue"
    
    # Si le domaine n'est pas à la cible
    } else {

        $administrator_password = ConvertTo-SecureString -AsPlainText -Force "[ad_password]"
        $administrator_credential = New-Object -Type "PSCredential" -ArgumentList "[domain]\[ad_admin]", $administrator_password

        # Check si le hostname est à la cible :
        if ($current_hostname -eq "[hostname]") {

            #Ajout du poste au domaine cible
            Add-Computer -DomainName "[domain]" -Credential $administrator_credential

        } else {

            #Changement du nom de l'ordinateur et jonction au domaine
            Add-Computer -DomainName "[domain]" -ComputerName $current_hostname -NewName "[hostname]" -Credential $administrator_credential 
            Write-Host "$current_hostname a été renomé [hostname]" -ForegroundColor "Green"
        }

        Write-Host "[hostname] est maintenant accosté au domaine [domain] " -ForegroundColor "Green"

        gpupdate /force
    }
    
    Write-Host "La configuration de [hostname] n'est pas encore terminée, mais l'ordinateur doit redémarrer." -ForegroundColor "Blue"
    pause
    
    # Redémarre l'ordinateur
    Restart-Computer
} 

#
#   Disable NetBIOS
#   

function disable_netbios {

    Print-Title -title "Désactivation du service NetBIOS" -color "Cyan"

    Start-Process wmic.exe -ArgumentList "/interactive:off nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2" -Wait
    Start-Process wmic.exe -ArgumentList "/interactive:off nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2" -Wait

    Write-Host "Le service NetBIOS a été désactivé" -ForegroundColor "Green"
    
}

#
#   Stop and disable all the unused services from the list
#

function disable_unused_services {

    Print-Title -title "Désactivation des services superflux" -color "Cyan"

    # Liste des services à désactiver
    $services_to_remove = @("stisvc", "iphlpsvc", "SCardSvr", "WpcMonSvc", "DiagTrack", "CscService", "MapsBroker", "RasMan", "XblAuthManager", "XblGameSave", "SharedAccess", "FrameServer", "BthAvctpSvc", "WbioSrvc", "RetailDemo", "lfsvc", "XboxNetApiSvc", "NetTcpPortSharing", "CDPSvc", "bthserv", "fhsvc", "ScDeviceEnum", "MSiSCSI", "WMPNetworkSvc", "icssvc", "PhoneSvc", "wisvc", "Spooler", "SCPolicySvc", "Fax", "TapiSrv", "WebClient", "WSearch")

    Foreach ($service in Get-Service) {

        if ($services_to_remove -contains $service.name) {

            # Arrêter et désactiver le service
            Get-Service -Name $service.name | Stop-Service -PassThru | Set-Service -StartupType "Disabled"
            Write-Host "Le service ", $service.name, " a été désactivé." -ForegroundColor "Green"   
        
        }
    }
}

#
#   Installation de l'agent SNMP
#

function install-snmp {

    Print-Title -title "Installation de l'agent SNMP" -color "Cyan"

    Install-WindowsFeature "SNMP-Service" -IncludeAllSubFeature -IncludeManagementTools
    Stop-Service -Name "SNMP"
    Stop-Service -Name "SNMPTRAP"
    Set-Service -Name "SNMP" -StartupType "Disabled"
    Set-Service -Name "SNMPTRAP" -StartupType "Disabled"

    $disk_letter = (Resolve-Path ".").ToString().Substring(0,2)
    $program_path = "$disk_letter\LOGICIELS\VC_redist_14.28\VC_redist.x64.exe"

    If (Test-Path "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\X64\") {

        Write-Host "VC Redist x64 est déjà installé" -ForegroundColor "Cyan" 

    } else {

        #Installation de VC Redistx64
        Start-Process $program_path
        Write-Host "VC Redist x64 a été installé" -ForegroundColor "Green" 
    }

    $agent_name = "NET-SNMP Agent"

    if ((Get-Service).name -contains $agent_name) {

        Write-Host "L'agent SNMP est déjà installé" -ForegroundColor "Cyan" 

    } else {

        try {

            # Copie du répertoire usr à la racine de C:\
            Copy-Item ".\net-snmp\usr" -Destination "C:\" -Recurse -Force
            Write-Host "Les source du service Net-SNMP ont été installées" -ForegroundColor "Green" 

            if (Get-Service -Name $agent_name -ErrorAction Ignore) {
                Invoke-Command 'sc delete "', $agent_name, '"'
            }

            # Parametres de configuration de l'agent SNMP
            $agent_data = @{
                Name = $agent_name
                DisplayName = $agent_name
                StartupType = "Automatic"
                BinaryPath = "C:\usr\bin\snmpd.exe -service"
            }

            #Enregistrement de l'agent NET-SNMP en tant que service
            New-Service @agent_data
            Write-Host "L'agent Net-SNMP a été configuré.:" -ForegroundColor "Green"

            #Lancement du service SNMP
            Restart-Service -Name $agent_name
            Write-Host "L'agent SNMP a été redémarré:" -ForegroundColor "Green"

            Invoke-Command 'C:\usr\bin\snmpwalk.exe -v3 -l authPriv -u "[snmp_user]" -a "[hash_algo]" -A "[hash_password]" -x "[crypto_algo]" -X "[crypto_password]" localhost'

        } catch {

            Write-Host "Les sources du service Net-SNMP n'ont pas pu être installées" -ForegroundColor "Red" 
            return
        }
    }
}

#
#
#

function try_static_routes {

    Print-Title -title "Test des interconnexions réseau" -color "Cyan"

    # Liste des adresses à tester
    $destinations = @([address_to_ping])

    # Pour chaque adresse dans la liste
    Foreach ($destination in $destinations) {

        Write-Host "Test de la connexion vers $destination..." -ForegroundColor "Cyan"

        # Si le ping abouti
        if (Test-Connection -Count 3 -Quiet -ErrorAction Ignore $destination) {

            Write-Host "La connexion vers $destination est opérationnelle`n" -ForegroundColor "Green"
        
        # Si le ping echoue
        } else {

            Write-Host "La connexion vers $destination est defaillante`n" -ForegroundColor "Red"
        }
    }
}

function install-nxlog {

    Print-Title -title "Installation du service NxLog" -color "Cyan"

    $agent_name = "NX-LOG Agent"

    if ((Get-Service).name -contains $agent_name) {

        Invoke-Command 'sc delete "$agent_name"'
        Write-Host "L'ancienne installation de NX-LOG est déjà supprimée" -ForegroundColor "Cyan" 
    }

    try {

        $source = ".\nxlog"
        $destination = "C:\Program Files (x86)\"
        Copy-Item $source -Destination $destination -Recurse -Force

        # Parametres de configuration de l'agent NX-LOG
        $agent_data = @{
            Name = $agent_name
            DisplayName = $agent_name
            StartupType = "Automatic"
            BinaryPath = '"C:\Program Files (x86)\nxlog\nxlog.exe" -c "C:\Program Files (x86)\nxlog\conf\nxlog.conf"'
        }

        # Enregistrement de l'agent NX-LOG en tant que service
        New-Service @agent_data
        Write-Host "L'agent NX-LOG a été configuré." -ForegroundColor "Green"

        # Lancement du service SNMP
        Restart-Service -Name $agent_name
        Write-Host "L'agent NX-LOG a été redémarré:" -ForegroundColor "Green"

    } catch {

        Write-Host "Le service NX-LOG ne peut pas être installé" -ForegroundColor "Red" 
        return
    }
}

function install_nfs {

    $RegistryPath = "Ordinateur\HKEY_LOCAL_MACHINES\SOFTWARE\Microsoft\ClientForNFS\CurrentVersion\Default"

    If (-NOT (Test-Path $RegistryPath)) {

        New-Item -Path $RegistryPath -Force | Out-Null
    }

    ##
    #
    #   Parameters:
    #   
    #       -Path: Path to the registy key
    #       -Name: Name of the registy key
    #       -Value: Value of the registry key (Default format: hexadecimal, 0x3E9 = 1001), the value is the user ID and group ID of the user owning the share point
    #
    New-ItemProperty -Path $RegistryPath -Name "AnonymousUID" -Value 0x3E9 -PropertyType DWORD -Force 
    New-ItemProperty -Path $RegistryPath -Name "AnonymousGID" -Value 0x3E9 -PropertyType DWORD -Force 
}

function create_task ($name, $description, $execute, $argument, $user, $password, $time = $null, $_event = $null) {

    if ($time) {
        
        $trigger = New-ScheduledTaskTrigger -Daily -At $time
    
    } 

    if ($_event) {

        $trigger = cimclass "MSFT_TaskEventTrigger" "root/Microsoft/Windows/TaskScheduler" | New-CimInstance -ClientOnly
        $trigger.Subscription = $_event
        $trigger.Enabled = $true
    }

    $action = New-ScheduledTaskAction -Execute $execute -Argument $argument
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType "S4U"
    $settings = New-ScheduledTaskSettingsSet -Compatibility "Win8" -MultipleInstances "Parallel"

    $task = New-ScheduledTask -Description $description -Trigger $trigger -Action $action -Principal $principal -Settings $settings
    $task | Register-ScheduledTask -TaskName $name -User $user -Password $password
}

#
#
#

function setup_tasks {
    
    Print-Title -title "Configuration des tâches planifiées" -color "Cyan"

    # Copie du fichier à la racine de C:\
    Copy-Item "$PSScriptRoot\tasks\Lancement_Panorama_Sur_Mur_Ecran.ps1" -Destination C:\ -Recurse

    ##
    #   Parameters:
    #
    #       -AsJob: Runs the cmdlet as a background job. Use this parameter to run commands that take a long time to complete.
    #       -Execute: Specifies the path to an executable file.
    #       -Argument: Specifies arguments for the command-line operation.
    #
    #   Documentation:
    #
    #       https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtaskaction?view=windowsserver2019-ps
    #
    $action = New-ScheduleTaskAction -AsJob -Execute 'Start-Process' -Arguments '-ExecutionPolicy ByPass "C:\Lancement_Panorama_Sur_Mur_Ecran.ps1"',

    ##
    #   Parameters:
    #
    #       -AtLogon: Indicates that a trigger starts a task when a user logs on.
    #
    #   Documentation:
    #
    #       https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger?view=windowsserver2019-ps
    #
    $trigger = New-ScheduledTaskTrigger -AtLogon

    ##
    #   Parameters:
    #
    #       -LogonType: Specifies the security logon method that Task Scheduler uses to run the tasks that are associated with the principal.
    #       -RunLevel: Specifies the level of user rights that Task Scheduler uses to run the tasks that are associated with the principal.
    #       -GroupId: Specifies the group ID that Task Scheduler uses to run the tasks that are associated with the principal.
    #
    #   Documentation:
    #
    #       https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtaskprincipal?view=windowsserver2019-ps
    #
    New-ScheduledTaskPrincipal -GroupId '[short_domain]\[service_account]' -RunLevel 'Limited' -LogonType 'Password'

    ##
    #   Parameters:
    #
    #       -TaskName: Specifies the name of a scheduled task.
    #       -Trigger: Specifies an array of one or more trigger objects that start a scheduled task. A task can have a maximum of 48 triggers.
    #       -Action: Specifies an array of one or more work items for the task to run. If you specify multiple actions, the computer runs them in order. You can specify up to 32 actions.
    #       -Principal: Specifies the security context in which a task is run.
    #
    #   Documentation:
    #
    #       https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask?view=windowsserver2019-ps
    #
    Register-ScheduledTask -TaskName "Lancement_Panorama_Sur_Mur_Ecran" -Action $action -Trigger $trigger -Principal $principal

    ##
    #   Parameters:
    #
    #       -TaskName: Specifies the name of a scheduled task.
    #
    #   Documentation:
    #
    #       https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/enable-scheduledtask?view=windowsserver2019-ps
    #
    Enable-ScheduledTask -TaskName "Lancement_Panorama_Sur_Mur_Ecran"

    ##
    #   Parameters:
    #
    #       -TaskName: Specifies the name of a scheduled task.
    #
    #   Documentation:
    #
    #       https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/start-scheduledtask?view=windowsserver2019-ps
    #
    Start-ScheduledTask -TaskName "Lancement_Panorama_Sur_Mur_Ecran"
}

function create_computers {

    Print-Title -title "Déplacement des ordinateurs" -color "Cyan"

    [computers]
}

function import_gpo {

    Print-Title -title "Importation des GPO (Group Policy Objects)" -color "Cyan"

    $gpo_list = [gpo_list]
    $domain = "[domain]"
    $gpo_path = Resolve-Path "./gpo/"
    $migration_table_path = Resolve-Path "./gpo/migration_table.migtable"

    foreach ($gpo in $gpo_list) {

        $name = $gpo.name
        $target = $gpo.target
        $permissions = $gpo.permissions

        if (-Not ($name -eq "Default Domain Policy")) {
            New-GPO $name | out-null
        }

        Import-GPO -BackupGpoName $name -TargetName $name -Path $gpo_path -MigrationTable $migration_table_path | out-null
        New-GPLink -Name $name -Target $target | out-null
        Write-Host "Importation de la GPO $name"

        if (-not ($permissions -contains "Utilisateurs authentifiés")) {

            Set-GPPermission -Replace -Name $name -TargetName "Utilisateurs authentifiés" -TargetType "Group" -PermissionLevel "None" -WarningAction "Ignore" | out-null
            Write-Host "    Suppression de la cible 'Utilisateurs authentifiés'"

            Foreach ($hostname in $permissions) {
                Set-GPPermission -Name $name -TargetName $hostname -TargetType "Computer" -PermissionLevel "GpoApply" | out-null
                Write-Host "    Ajout de la cible '$hostname'"
            }
        }
    }
}

function install_ntp_window() {

    w32tm /config /manualpeerlist:"[ntp_window]" /syncfromflags:manual
}

function install_licences() {

    slmgr -ipk "[licences]"
}

function install_ad() {

    Print-Title -title "Installation du serveur ActiveDirectory" -color "Cyan"

    Install-windowsfeature -name "AD-Domain-Services" -IncludeManagementTools

    $administrator_password = ConvertTo-SecureString -AsPlainText -Force "[ad_server_password]"
    $administrator_credential = New-Object -Type "PSCredential" -ArgumentList "[ad_server_login]", $administrator_password

    Install-ADDSForest `
    -SafeModeAdministratorPassword $administrator_password `
    -DomainName "[domain]" `
    -InstallDns `
    -Force

    exit
}

function setup_usb_blocking () {

    Copy-Item ".\USB" -Destination "C:\" -Recurse -Force

    foreach ($disk in Get-Disk) {
        $SerialNumber = $disk.SerialNumber.Trim()
        $SerialNumber >> "C:\USB\whitelist.txt"
        Write-Host "Ajout du numéro de série '$SerialNumber' dans la liste blanche."
    }
}

function install_vmware_tools () {

    Print-Title -title "Installation des VMWare Tools" -color "Cyan"

    $disk_letter = (Resolve-Path ".").ToString().Substring(0,2)
    $tools_path = "$disk_letter\LOGICIELS\VMWare_tools_11.1\VMware-tools-11.1.0-16036546-x86_64.exe"
    (Start-Process $tools_path -ArgumentList '/v "/qn REBOOT=R ADDLOCAL=ALL REMOVE=AppDefense,FileIntrospection,NetworkIntrospection,Hgfs"' -PassThru).WaitForExit()
    Write-Host "VMWare tools installés."
}

function add_dns_entries() {

    Print-Title -title "Suppression des anciennes entrées DNS" -color "Cyan"

    $dns_records = Get-DnsServerResourceRecord -ZoneName "[domain]" -RRType "A" -Name "@"

    ForEach ($dns_record in $dns_records) {
        Write-Host "Suppression de $dns_record.HostName"
        Remove-DnsServerResourceRecord -ZoneName "[domain]" -InputObject $dns_record -Force 
    }

    Print-Title -title "Ajout des entrées DNS (Domain Name Service)" -color "Cyan"

    $dns_entries = @([dns_entries])

    ForEach ($dns_entry in $dns_entries) {

        if (Get-DnsServerResourceRecord -Name $dns_entry.name -ZoneName "[domain]" -ErrorAction "SilentlyContinue") {

            Write-Host "$($dns_entry.name) already exists."
        
        } else {
            
            Add-DnsServerResourceRecordA -Name $dns_entry.name -ZoneName "[domain]" -IPv4Address $dns_entry.ip
            Write-Host "$($dns_entry.name) created."
        }
    }
}


function add_users() {

    Print-Title -title "Ajout des groupes et utilisateurs" -color "Cyan"

[units]
[users]
[groups]
[members]
}

function install_wdac() {

    $Emplacement_Strategie_Audit_XML            = "C:\wdac\WDAC_Audit.xml"
    $Emplacement_Strategie_Audit_Temporaire     = "C:\wdac\WDAC_Audit_Temp.xml"
    $Emplacement_Strategie_Audit_Binaire        = "C:\wdac\WDAC_Audit.bin"
    $Emplacement_Strategie_Applique_XML         = "C:\wdac\WDAC_Applique.xml"
    $Emplacement_Strategie_Applique_Binaire     = "C:\wdac\WDAC_Applique.bin"
    $DestinationBinaire                         = $env:windir+"\system32\CodeIntegrity\SiPolicy.p7b"

    Copy-Item ".\wdac" -Destination "C:\" -Recurse -Force

    ConvertFrom-CIPolicy $Emplacement_Strategie_Audit_XML $Emplacement_Strategie_Audit_Binaire
     
    New-CIPolicy -audit -Level Hash -FilePath $Emplacement_Strategie_Audit_Temporaire -UserPEs
    Merge-CIPolicy -PolicyPaths $Emplacement_Strategie_Audit_XML, $Emplacement_Strategie_Audit_Temporaire -OutputFilePath $Emplacement_Strategie_Applique_XML
    Remove-Item -Path $Emplacement_Strategie_Audit_Temporaire -Force -Confirm:$false
    Set-RuleOption -FilePath $Emplacement_Strategie_Applique_XML -Option 3 -Delete
    ConvertFrom-CIPolicy $Emplacement_Strategie_Applique_XML $Emplacement_Strategie_Applique_Binaire
    Copy-Item -Path $Emplacement_Strategie_Applique_Binaire -Destination $DestinationBinaire
    Invoke-CimMethod -Namespace "root/Microsoft/Windows/CI" -ClassName "PS_UpdateAndCompareCIPolicy" -MethodName "Update" -Arguments @{FilePath = $DestinationBinaire}
}

function update_hostname() {

    Rename-Computer -NewName "[hostname]" -Force -Restart
}

function reboot() {

    Restart-Computer
}

########## MAIN

Clear-Host

Write-Host "  __  __ ___ ___  ____   "
Write-Host " |  \/  |_ _/ _ \/ ___|  "
Write-Host " | |\/| || | | | \___ \  "
Write-Host " | |  | || | |_| |___) | "
Write-Host " |_|  |_|___\___/|____/  "

Print-Title -title "Début de la configuration de [hostname]" -color "Cyan"

$current_hostname = Hostname
$steps = @()

if (-not ($current_hostname -eq "[hostname]")) {
 
    $steps += @{question = "Renommer le serveur ?"; action = "update_hostname"}
}

if ([has_tree_update]) {

    $steps += @{question = "Mettre à jour l'arborescence ?"; action = "update_tree"}
}

if ([has_drivers]) {

    $drivers = [drivers]

    Foreach ($driver in $drivers) {
        $steps += @{question = "Installer le driver $driver ?"; action = "install_driver $driver"}
    }
}

if ([has_vmware_tools]) {

    $steps += @{question = "Installer les VMWare Tools ?"; action = "install_vmware_tools"}
}

if ([has_certificates]) {

    $steps += @{question = "Installer les certificats ?"; action = "install_certificates"}
}

$steps += @{question = "Désactiver le service NetBIOS ?"; action = "disable_netbios"}
$steps += @{question = "Désactiver les services Windows superflux ?"; action = "disable_unused_services"}

if ([has_event_logs]) {

    $steps += @{question = "Mettre-a-jour le status des journeaux d'evenements ?"; action = "update_event_logs"}  
}

if ([has_ip]) {

    [network]
}

if ([has_routes]) {

     [routes_question]
}

if ([has_dns]) {

    [dns]
}

if ([has_nxlog]) {

    $steps += @{question = "Lancer l'installation de service NxLog ?"; action = "install-nxlog"}
}

if ([has_snmp]) {

    $steps += @{question = "Lancer l'installation de l'agent SNMP ?"; action = "install-snmp"}
}
if ([has_ntp_window]) {

    $steps += @{question = "Configurer le NTP ?"; action = "install_ntp_window"}
}
if ([has_licences]) {

    $steps += @{question = "Parametrer la clef de licence ?"; action = "install_licences"}
}

#if ([tasks]) {
#
#    $steps += @{question = "Configurer les tâches planifiées ?"; action = "setup_tasks"}
#}

if ([install_ad]) {

    if ($current_hostname -eq "[hostname]") {

        $steps += @{question = "Installer le service Active Directory ?";   action = "install_ad"} 
        $steps += @{question = "Ajouter les entrées DNS ?";                 action = "add_dns_entries"} 
        $steps += @{question = "Ajouter les groupes et utilisateurs ?";     action = "add_users"}

        if ([has_gpo]) {

            $steps += @{question = "Créer les ordinateurs ?"; action = "create_computers"}
            $steps += @{question = "Importer les GPO (Group Policy Object) ?"; action = "import_gpo"}
        }
    }

} else {

    $steps += @{question = "Joindre [hostname] au serveur Active Directory ?"; action = "join_domain"}
}

if ([has_usb_blocking]) {
    $steps += @{question = "Mettre en place le blocage USB ?"; action = "setup_usb_blocking"}
}

if ([has_tasks]) {

    $tasks = [tasks]

    Foreach ($task in $tasks) {
        $steps += @{question = "Configurer les taches planifiees ?"; action = "create_task -name '$($task.name)' -description '$($task.description)' -execute '$($task.execute)' -argument '$($task.argument)' -user '$($task.user)' -password '$($task.password)' -_event '$($task.event)' -time '$($task.time)'"}
    }
}

if ([has_wdac]) {

    $steps += @{question = "Installer le profile WDAC : [wdac_profile] ?"; action = "install_wdac"}
}

$steps += @{question = "Redémarrer [hostname] ?"; action = "reboot"}

Foreach ($step in $steps) { 

    ask -title "Configuration de [hostname]" -question $($step.question) -action $($step.action) -delay 10 -default_answer "y"
}