$Emplacement_Strategie_Audit_XML            = ".\WDAC_Audit.xml"
$Emplacement_Strategie_Audit_Temporaire     = ".\WDAC_Audit_Temp.xml"
$Emplacement_Strategie_Applique_XML         = ".\WDAC_Applique.xml"
$Emplacement_Strategie_Applique_Binaire     = ".\WDAC_Applique.bin"
$DestinationBinaire                         = $env:windir+"\system32\CodeIntegrity\SiPolicy.p7b"

New-CIPolicy -audit -Level Hash -FilePath $Emplacement_Strategie_Audit_Temporaire -UserPEs
Merge-CIPolicy -PolicyPaths $Emplacement_Strategie_Audit_XML, $Emplacement_Strategie_Audit_Temporaire -OutputFilePath $Emplacement_Strategie_Applique_XML
Remove-Item -Path $Emplacement_Strategie_Audit_Temporaire -Force -Confirm:$false
Set-RuleOption -FilePath $Emplacement_Strategie_Applique_XML -Option 3 -Delete
ConvertFrom-CIPolicy $Emplacement_Strategie_Applique_XML $Emplacement_Strategie_Applique_Binaire
Copy-Item -Path $Emplacement_Strategie_Applique_Binaire -Destination $DestinationBinaire
Invoke-CimMethod -Namespace "root/Microsoft/Windows/CI" -ClassName "PS_UpdateAndCompareCIPolicy" -MethodName "Update" -Arguments @{FilePath = $DestinationBinaire}

Restart-Computer