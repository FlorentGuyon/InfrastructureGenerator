<#
#    SCRIPT DE CONFIGURATION D'UN SERVEUR VEEAM BACKUP & REPLICATION

Ce programme permet d'assurer automatiquement toute la configuration d'un serveur de sauvegarde. 
Il se charge de la creation des utilisateurs, des serveurs a sauvegarder, des listes auquelles ces serveurs appartiennent, des jobs de sauvegardes ainsi que des serveurs de stoquage sur lesquels sont conserves les sauvegardes.
Les serveurs pris en charge par ce script sont les serveurs physiques windows et Linux ainsi que des hyperviseurs VMWare ESXI.
#>

Clear-Host


###
# Constantes
###

    # Définir un mot de passe du compte de service utilisé par Veeam, ce compte est présent dans l'Active Directory.
    $Compte_Service_User   = [compte_service_login]
    $Compte_Service_MDP    = [compte_service_password]
    
    $Credential                  = @()

    $Container                   = @()

#<------------------------- Florent  ------------------------->#
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
    $answer_id = $sh.Popup($question, $delay, $title, 3+32)

    # Timeout
    if ($answer_id -eq -1) {

        $answer_id = $default_answer_id
    }

    # Yes
    if ($answer_id -eq 6) {

        Invoke-Expression $action
    }

    if ($answer_id -eq 2){
        fatal_error
    }
}

function print_title ($title, $color) {

    $frame = "`n"
    $frame += "    ####" + ("#" * $title.Length) + "####`n"
    $frame += "    #   " + (" " * $title.Length) + "   #`n"
    $frame += "    #   " + $title                + "   #`n"
    $frame += "    #   " + (" " * $title.Length) + "   #`n"
    $frame += "    ####" + ("#" * $title.Length) + "####`n"

    Write-Host $frame -ForegroundColor $color
}

function fatal_error($text) {

    Write-Host $text

    Write-Host "Fin de la configuration de Veeam Backup & Replication."
    Exit
}
#<------------------------- Florent  ------------------------->#

#<------------------------- Fonction - Credentials  ------------------------->#
Function Credentials {
   
    <#
    Créer et maintenir une liste d'enregistrements d'informations d'identification (Crédentials) que vous prévoyez d'utiliser pour vous connecter aux composants de l'infrastructure de sauvegarde.
    #>
    
    ###
    # Variables
    ###

    # Dictionnaire de credentials. Il contient les données suivantes : "id", "type", "login", "password".
    $Credentials_Data = [credentials_data]

    print_title -title "Configuration du credential pour les hôtes Linux, Windows et les Hyperviseurs WMWare ESXI" -color "Cyan"

    Foreach ($Current_Credential in $Credentials_Data){

        # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/get-vbrcredentials.html        
        $Get_Credential = Get-VBRCredentials -Name ($Current_Credential).id

        # Si inexistant, selon le type de credential (Linux, Windows ou VMWare ESXI), un credential spécifique est créé.
        if ($Get_Credential -eq $null) {

            # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/add-vbrcredentials.html?ver=110
            if (($Current_Credential).type -eq "linux"){

                $Credential.Add(($Current_Credential).id) = Add-VBRCredentials -Type Linux -User ($Current_Credential).login -Password ($Current_Credential).password -ElevateToRoot -FailoverToSu -RootPassword $Compte_Service_MDP
            }

            elif (($Current_Credential).type -eq "windows"){

                $Credential.Add(($Current_Credential).id) = Add-VBRCredentials -Type Windows -User ($Current_Credential).login -Password ($Current_Credential).password
            }
            
            # Si la configuration échoue, elle se termine.
            else {
    
                fatal_error ("Une erreur est survenue. '"+ ($Current_Credential).type +"' n'est pas reconnue comme un type valide.")
            }
        }
    }
}

#<------------------------- Fonction - Serveur Repository    ------------------------->#
Function Serveur_Repository {
   
    <#
    Un répertoire de sauvegarde (Repository) est un emplacement de stockage où Veeam conserve les fichiers de sauvegarde, les copies de VM et les métadonnées pour les VM répliquées.
    #>

    <#    
    Types de serveurs de stockage : [ WinLocal ; LinuxLocal ; CifsShare ; ExaGrid ; DataDomain ; HPStoreOnceIntegration ; Quantum ; Nfs
    #>

    ###
    # Variables
    ###

    # Dictionnaire de serveur de stockage. Il contient les données suivantes : "id", "type", "hostname", "credentials", "path".
    $SRV_Backup_Data = [srv_backup_data]

    print_title -title "Configuration de l'ensemble des serveurs de sauvegarde." -color "Cyan"

    Foreach ($Backup in $SRV_Backup_Data){
        
        # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/get-vbrserver.html?ver=110
        # Vérification de la présence du serveur dans l'infrastructure Veeam.
        $Presence_SRV = Get-VBRServer -Name ($Backup).id
           
        if ($Presence_SRV -eq $null){
            # Selon le type de serveur, ajout de ce dernier.

            <#
            Type de serveurs : [ BackupServer ; VC ; ESXi ; VcdSystem ; Scvmm ; HvServer ; HvCluster ; SmbCluster ; SmbServer ; Windows ; Linux ; Cloud ; Local ; SanHost ]
            #>

            if (($Backup).type_serveur -eq "Linux"){

                # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/add-vbrlinux.html?ver=110
                Add-VBRLinux -Name ($Backup).id -Credentials $Credential.(($Backup).credentials) -Description "Serveur Linux de stockage des sauvegarde."
            }

            elif (($Backup).type_serveur -eq "Windows"){
                
                # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/add-vbrwinserver.html?ver=110
                Add-VBRWinServer -Name ($Backup).id -Credentials $Credential.(($Backup).credentials) -Description "Serveur Windows de stockage des sauvegarde."
            }

            else {
                fatal_error ("Une erreur est survenue. '"+ ($Backup).id +"' n'est pas reconnue comme un serveur de stockage valide.")
            }
        }

        # Si le serveur de sauvegarde est déjà présent dans l'infrastructure, il vérifie son attribution.
        else {
            # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/get-vbrbackuprepository.html?ver=110
            $Get_SRV_Sauvegarde = Get-VBRBackupRepository -Name ($Backup).id

            # Si ce serveur de stockage est inexistant, il en créé un.
            if ($Get_SRV_Sauvegarde -eq $null) {

                # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/add-vbrbackuprepository.html
                $Stockage = Add-VBRBackupRepository -Name ($Backup).id -Type ($Backup).type -Server ($Backup).hostname -Credentials $Credential.(($Backup).credentials) -Folder ($Backup).path
            }   
                # Si la configuration échoue, elle se termine.
            else {
    
                fatal_error ("Une erreur est survenue. '"+ ($Backup).id +"' n'est pas reconnue comme un serveur de stockage valide.")
            }
        }
    }
}

#<------------------------- Fonction - Contenaires    ------------------------->#
Function Contenaires {

    <#
    Spécifie les credentials spécifique à chaque machine.
    #>

    ###
    # Variables
    ###

    # Dictionnaire d'hôtes. Il contient les données suivantes : "id", "type", "hostname", "credentials".
    $CC_Data = [cc_data]

    print_title -title "Ajout des credentials personnalisées pour chaque machine présente dans l'infrastructure de sauvegarde." -color "Cyan"

    Foreach ($CC in $CC_Data){
        # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/new-vbrindividualcomputercustomcredentials.html
        $Custom_Credentials = New-VBRIndividualComputerCustomCredentials -HostName ($CC).hostname -Credentials $Credential.(($CC).credentials)
        $Container.Add($CC.id) = New-VBRIndividualComputerContainer -CustomCredentials $Custom_Credentials
    }
}

#<------------------------- Fonction - Création des groupes de protections    ------------------------->#
Function Groupe_Protection {
    
    <#
    Spécifie les credentials spécifique à chaque machine.
    #>

    ###
    # Variables
    ###

    $GP_Data = [gp_data]

    Foreach ($GP in $GP_Data){
        
        # Vérification de la présence du groupe de protection.
        # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/get-vbrprotectiongroup.html
        $Get_GP = Get-VBRProtectionGroup

        # En l'absence de ce dernier, un nouveau est ajouté.
        if ($Get_GP -contains ($GP).id) {

            Write-Host "Le groupe de protection existe déjà. Le voici : ($GP).id"
        }
    
        # En l'absence de groupe de protection. Un nouveau est créé.
        else {
            
            # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/add-vbrprotectiongroup.html
            Add-VBRProtectionGroup -Name ($GP).id -Container ($GP).containers
               
            # Autoriser de la découverte des membres du groupe.
            # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/enable-vbrprotectiongroup.html
            Enable-VBRProtectionGroup -ProtectionGroup ($GP).id
            Write-Host "La découverte de groupe par les membres est actif."

            # Démarrer la découverte des membres du groupe.
            # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/rescan-vbrentity.html
            Rescan-VBREntity -Entity ($GP).id
            Write-Host "La découverte de groupe par les membres à démarrée."
        }
    }
}

#<------------------------- Fonction - Création des groupes de protections    ------------------------->#
Function Jobs {

    print_title -title "Configuration de l'ensemble des jobs." -color "Cyan"

    # Dictionnaire de Jobs. Il contient les données suivantes : 
    $Jobs_Data = [jobs_data]

    Foreach ($Job in $Jobs_Data){

        # Vérification de la présence du job.
        # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/get-vbrcomputerbackupjob.html?ver=110
        $Get_Job = Get-VBRComputerBackupJob -Name ($Job)name
        
        if ($Get_Job -eq $null){    
            
            # Définir les options quotidienne.
            # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/new-vbrdailyoptions.html
            $Job_Daily_Options = New-VBRDailyOptions -Type ($Job).options_frequence -Period ($Job).time

            # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/new-vbrserverscheduleoptions.html
            $Job_Schedule = New-VBRServerScheduleOptions -Type ($Job).frequence -DailyOptions $Job_Options
        
            # Création du job Linux.
            # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/add-vbrcomputerbackupjob.html
            Add-VBRComputerBackupJob -Name "($Job).name" -OSPlatform "($Job).plateform" -Type "($Job).type" -Mode ManagedByBackupServer -BackupObject "($Job).protection_groups" -BackupRepository "($Job).backup_repository" -BackupType EntireComputer -EnableSchedule -ScheduleOptions $Job_Schedule 
        }

        # Si la configuration échoue, elle se termine.
        else {
            Write-Host "La configuration du job à échouée"
        }
    }
}
                                       # Suppressions
##########################################################################################################

#<------------------------- Fonction - Suppression - Jobs    ------------------------->#
Function Suppression_Jobs {
        
    print_title -title "Suppression de l'ensemble des Jobs existants." -color "Cyan"

    ###
    # Variable
    ###

    # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/get-vbrcomputerbackupjob.html
    $Jobs_Data = Get-VBRComputerBackupJob

    # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/remove-vbrcomputerbackupjob.html   
    Foreach ($Job in $Jobs_Data){
        Write-Host "Suppression de $Job en cours..."
        Remove-VBRComputerBackupJob -Job $Job
    }
}

#<------------------------- Fonction - Suppression - Groupes de protections    ------------------------->#
Function Suppression_GP {
    
    print_title -title "Suppression de l'ensemble de tous les groupes de protections existants." -color "Cyan"

    ###
    # Variable
    ###

    # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/get-vbrprotectiongroup.html
    $GP_Data = Get-VBRProtectionGroup

    # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/remove-vbrprotectiongroup.html 
    Foreach ($GP in $GP_Data){
        Write-Host "Suppression de $GP en cours..."
        Remove-VBRProtectionGroup -ProtectionGroup $GP
    }
}

#<------------------------- Fonction - Suppression - Backup    ------------------------->#
Function Suppression_Backup {
    
    print_title -title "Suppression de l'ensemble de tous les serveurs de sauvegarde." -color "Cyan"

    ###
    # Variable
    ###

    # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/get-vbrbackuprepository.html
    $Backup_Data = Get-VBRBackupRepository

    # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/remove-vbrbackuprepository.html
    Foreach ($Backup in $Backup_Data){
        Write-Host "Suppression de $Backup en cours..."
        Remove-VBRBackupRepository -Repository $Backup
    }
}

#<------------------------- Fonction - Suppression - Credentials    ------------------------->#
Function Suppression_Credentials {
    
    print_title -title "Suppression de l'ensemble des Credentials existants." -color "Cyan"

    ###
    # Variable
    ###

    # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/get-vbrcomputerbackupjob.html
    $Credentials_Data = Get-VBRCredentials

    # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/remove-vbrcredentials.html?ver=110  
    Foreach ($Credential in $Credentials_Data){
        Write-Host "Suppression de $Credential en cours..."
        Remove-VBRCredentials -Credential $Credential
    }
}

##########################################################################################################

#<------------------------- Fonction - Introduction au script   ------------------------->#
Function Introduction {

    Clear-Host

    Write-Host "  __  __ ___ ___  ____   "
    Write-Host " |  \/  |_ _/ _ \/ ___|  "
    Write-Host " | |\/| || | | | \___ \  "
    Write-Host " | |  | || | |_| |___) | "
    Write-Host " |_|  |_|___\___/|____/  "

    print_title -title "Début de la configuration de Veeam Backup & Replication" -color "Cyan"
}

#<------------------------- Fonction - Introduction au script   ------------------------->#
Function Questions {

    $steps = @(
        @{question = "Voulez-vous supprimer l'ensemble des Jobs existants ?";                     action = "Suppression_Jobs"},
        @{question = "Voulez-vous supprimer l'ensemble des groupes de protections existants ?";   action = "Suppression_GP"},
        @{question = "Voulez-vous supprimer l'ensemble des serveur de sauvegarde existants ?";    action = "Suppression_Backup"},
        @{question = "Voulez-vous supprimer l'ensemble des credentials existants ?";              action = "Suppression_Credentials"},
        @{question = "Voulez-vous configurer l'ensemble des credentials ?";                       action = "Credentials"},
        @{question = "Voulez-vous configurer le serveur de stockage 'Repository' ?";              action = "Serveur_Repository"},
        @{question = "Voulez-vous configurer les containers ?";                                   action = "Contenaires"},
        @{question = "Voulez-vous configurer les groupes de protections ?";                       action = "Groupe_Protection"},
        @{question = "Voulez-vous configurer l'ensemble des Jobs ?";                              action = "Jobs"}
    )

    Foreach ($step in $steps) { 

        ask -title "Configuration de [hostname]" -question $($step.question) -action $($step.action) -delay 30 -default_answer "y"
    }

    print_title -title "Fin de la configuration de Veeam Backup & Replication" -color "Cyan"    
}

#<------------------------- Main   ------------------------->#

Introduction
Questions



#<------------------------- Fonction - Gestion des hôtes    ------------------------->#
<#

Function Hotes {
   
    <#
    Un hôte est un système qui doit être sauvegarde par Veeam Backup & Repository. 
    Il peut s'agir d'un serveur physique Windows, Linux ou un Hyperviseur VMWare ESXI.
    

    print_title -title "Configuration de l'ensemble des hôtes Linux, Windows et VMWare ESXI." -color "Cyan"
    
    ForEach ($Host in $Dictionnaire_Hotes) {
        
        # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/get-vbrserver.html
        $Get_Host = Get-VBRServer -Name ($Host).id

        if ($Hote -eq $null){

            if (($Host).type -eq "linux"){

                # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/add-vbrlinux.html
                $Hotes = Add-VBRLinux -Name ($Host).id -Credentials ($Host).credentials
            }

            elif (($Host).type -eq "windows"){   
        
                # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/add-vbrwinserver.html
                $Hote = Add-VBRWinServer -Name ($Host).id -Credentials ($Host).credentials
            }
        
            elif (($Host).type -eq "esxi"){  

                # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/add-vbresxi.html
                $Hote = Add-VBRESXI -Name ($Host).id -Credentials ($Host).credentials
            }

            # Si la configuration échoue, elle se termine.
            else {
    
                fatal_error ("Une erreur est survenue. '"+ ($Host).id +"' n'est pas reconnue comme un hôte valide.")
            }
        }
    }
}
#>

#<------------------------- Fonction - A voir    ------------------------->#
Function a_voir {

    
    <#
    Un hôte est un système qui doit être sauvegarde par Veeam Backup & Repository. 
    Il peut s'agir d'un serveur physique Windows, Linux ou un Hyperviseur VMWare ESXI.
    #>

    print_title -title "Configuration des Hyperviseurs VMWare ESXI." -color "Cyan"

    ###
    # Variables
    ###
    
    # Liste machines virtuelles
    #    Documentation : https://helpcenter.veeam.com/docs/backup/powershell/find-vbrvientity.html
    $ESXI_Liste_VM = Find-VBRViEntity -Server $ESXI_Serveur
    Write-Host "La liste des machines virtuelles est la suivante : $ESXI_Liste_VM"
    
    ForEach ( $ESXI_VM in $ESXI_Liste_VM ) {

        Write-Host $ESXI_VM
    }

    #Nommage des job ESXI
    $ESXI_Job_Nom = "BACKUP_" + $ESXI_Serveur
    
    # Définir les jobs ESXI
    $ESXI_Job = Get-VBRJob -Name $ESXI_Job_Nom
    
    # En l'absence de job, il en créé.
    if ($ESXI_Job -eq $null) {
    
        # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/add-vbrvibackupjob.html
        $ESXI_Job = Add-VBRViBackupJob -Name $ESXI_Job_Nom -BackupRepository $Hostname_Serveur_Stockage -Entity $ESXI_Liste_VM
        
        # Si la configuration échoue, elle se termine.
        if ( $ESXI_Job -eq $null ) {
    
            fatal-error
        }
    }
    
    else {

        Write-Host "Le Job ESXI existe déjà."
    }

    # Récupération de la tâche programmée du Job.
    $ESXI_Job_Programmee = Get-VBRJobScheduleOptions -Job $ESXI_Job

    # En l'absence de la tâche programmée, un nouveau est créé.
    if ($ESXI_Job_Programmee -eq $null ) {

        # Documentation : https://helpcenter.veeam.com/docs/backup/powershell/set-vbrjobschedule.html
        Set-VBRJobSchedule -Job $ESXI_Job -Daily -At "[veeam_job_esxi_quotidienne_periode]"
        $ESXI_Job_Programmee = Get-VBRJobScheduleOptions -Job $ESXI_Job

        # En l'absence de Job, un nouveau est créé.
        if ( $ESXI_Job -eq $null ) {
    
            fatal-error
        }
    }
    
    else {

        Write-Host "La tâche programmée existe déjà."
    }

    # Activation de le planning de sauvegarde du serveur
    Enable-VBRJobSchedule -Job $ESXI_Job
    Write-Host "La tâche programmée de sauvegarde est activée."
}

