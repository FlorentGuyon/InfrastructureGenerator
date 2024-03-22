$Emplacement_Strategie_Audit_XML            = ".\WDAC_Audit.xml"
$Emplacement_Strategie_Applique_XML         = ".\WDAC_Applique.xml"
$Emplacement_Strategie_Audit_Binaire        = ".\WDAC_Audit.bin"
$DestinationBinaire                         = $env:windir+"\system32\CodeIntegrity\SiPolicy.p7b"

if (Test-Path -Path $Emplacement_Strategie_Applique_XML -PathType Leaf) {
    cp $Emplacement_Strategie_Applique_XML $Emplacement_Strategie_Audit_XML -Force -Confirm:$false
}
Set-RuleOption -FilePath $Emplacement_Strategie_Audit_XML -Option 3
ConvertFrom-CIPolicy $Emplacement_Strategie_Audit_XML $Emplacement_Strategie_Audit_Binaire
Copy-Item -Path $Emplacement_Strategie_Audit_Binaire -Destination $DestinationBinaire
Invoke-CimMethod -Namespace "root/Microsoft/Windows/CI" -ClassName "PS_UpdateAndCompareCIPolicy" -MethodName "Update" -Arguments @{FilePath = $DestinationBinaire}