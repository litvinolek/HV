############################################################################################################
# Get-HyperVInventory-MultipleReports.ps1
# add-on script for Get-HyperVInventory.ps1
# creates separate reports for a Hyper-V cluster, all Hyper-V hosts in the cluster, and each VM
# launch this directly on one of the servers to document
#
# version 1.0
# date 2015-12-21
# by Nils Kaczenski
############################################################################################################


############################################################################################################
function Check-Cluster()
{
$Result = $false

# a client cannot be in a cluster
if ($IsClient -eq $false)
{
  # check if a cluster is present
  $isClusterInstalled = (Get-WindowsFeature Failover-Clustering -ErrorAction SilentlyContinue).Installed
  if ($IsClusterInstalled -eq $true) 
  {
    $Result = $true
  }
  Return $Result
}
}

# check for server
$IsClient = (((Get-CimInstance Win32_OperatingSystem).Caption).contains('Server') -eq $false)

# get timestamp
$myTime = Get-Date -Format 'yyyyMMdd-HHmmss'

# set output path
$path = "$env:userprofile\Documents\"

# get script path
$MyPath = (Split-Path -parent $MyInvocation.MyCommand.Definition)

Set-Location $MyPath

'wait ...'

if (Check-Cluster)
{
  .\Get-HyperVInventory.ps1 -mode ClusterOnlyInventory -output ($path + 'HyperV-Cluster-' + $myTime + '.html') -noview $true
  $clusterNodes = (Get-ClusterNode | Sort-Object Name)
} else {
  $clusterNodes = ($env:COMPUTERNAME)
}

# get hosts
foreach ($Node in $clusterNodes)
{
  .\Get-HyperVInventory.ps1 -mode RemoteHostOnlyInventory -remoteHost $Node -output ($path + 'HyperV-Host-' + $Node + '-' + $myTime + '.html') -noview $true
  $VMs = (Get-VM -ComputerName $Node | Sort-Object Name)
  foreach ($VM in $VMs)
  {
    .\Get-HyperVInventory.ps1 -mode SingleVMInventory -remoteHost $Node -VMName $VM.Name -output ($path + 'HyperV-VM-' + $VM.Name + '-' + $myTime + '.html') -noview $true
  }
}

'Finished.'
