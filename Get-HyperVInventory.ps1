<#
 
.SYNOPSIS
Get-HyperVInventory.ps1 is a PowerShell script to create documentation reports (plain text or HTML) of single Hyper-V host servers or complete Hyper-V failover clusters.
It should work with Windows Server 2012 and later and with client Hyper-V on Windows 8 and later.
Launch it as an Administrator locally on a Hyper-V host server.
 
.DESCRIPTION
Get-HyperVInventory reads configuration data from Hyper-V host servers and writes them to a text or HTML file in a structured way. It is designed to be an inventory and reporting tool. It does not include performance or health data.
The script does not change anything on the systems. It only reads data and writes a text file. Thus, it is not "harmful" by itself.
It may, however, create significant load on your host servers if you run it in a very large environment.
The reports may include confidential data. So you should make sure to handle the reports adequately.
The script has multiple operation modes that let you choose between a full cluster inventory (including all host servers and all VMs), an inventory of just the local host server (including or excluding all VMs), a cluster core inventory or VM inventories. 
Some data is only reported to Administrators so you must launch the script from an elevated PowerShell session.
If you report on a cluster you need Administrator rights on all cluster nodes.

See the README.txt file for prerequisites and additional information.

Features:
This is only a small compilation of the data the script gathers:
- Hyper-V failover clusters: cluster core data, cluster networks, cluster storage
- Hyper-V host servers: OS details, CPUs (and cores), RAM, host networking, virtual switches, replication, Live Migration
- VMs: general data, CPU, RAM, networking, disks, Integration Services

Neither the author nor the company can provide any warranty for the script and will accept no liability. Use at your own risk.

.PARAMETER output
optional, String
	Define where Get-HyperVInventory.ps1 writes its output. To do so, specify the parameter -output with complete filepath with extension.
	Example:
		-output "C:\some\path\to\your\file.txt"
	If you leave this parameter out the script will generate a filename with a timestamp and store it in the current user's Documents folder.
 
.PARAMETER mode
optional, String
	Specify the script's mode. Currently there are five modes:
	  ClusterFullInventory - tries to identify the failover cluster that the local host belongs to and then to get complete information on the cluster, on each host, and on all VMs placed on each host.
		If the host is not part of a cluster (or it cannot identify it) the script will automatically switch to SingleHost mode.
	  LocalHostInventory - creates a report of the local host only, including information on all VMs placed on it.
	  RemoteHostInventory - creates a report of a specific remote host only, including information on all VMs placed on it. You must name the host with -remoteHost.
	  ClusterOnlyInventory - creates a report of the cluster configuration only, without host and VM details.
	  VMInventoryCluster - creates a report of all VMs in the cluster and all non-clustered VMs on each host.
    VMInventoryHost - creates a report of all VMs on the local host.
	Example:
	  -mode LocalHostInventory
	If you leave this parameter out the script will start with a manual selection of the modes. So to fully automate the inventory process you need to specify the mode.

.PARAMETER remoteHost
optional, String
  Specify the name of a remote host to report on. This parameter is mandatory if you select the mode RemoteHostInventory.
	Example:
	  -remoteHost HV07

.PARAMETER format
optional, String
	Specify the format for the report file. There is a choice of two:
	  HTML - creates a report file in HTML format, good to read and compatible with all browsers. This might, however, result in a very large file for full inventories.
    TXT - creates a report file in plain text format. The file size is smaller but the output may be harder to read.
	Example:
	  -format TXT
	If you leave this parameter out the script will create an HTML file.

.PARAMETER noview
optional, Boolean
	Specify if you want to suppress the automatic display of the created report file. Set -noview $true if you do NOT want to open the report.
	Example:
	  -noview $true
	If you leave this parameter out or set it to $false the report file will be opened in your default text editor at the end of the script's execution. For full automatization you will want to suppress this.

 
.EXAMPLE
./Get-HyperVInventory.ps1
This launches the script and displays a small menu of operation modes to choose from. Type the respective number to start reporting.

.EXAMPLE
./Get-HyperVInventory.ps1 -output "C:\some\path\to\your\file.txt" -format TXT -mode ClusterFullInventory -noview $true
This launches the script in fully automated mode (will not open the report at the end) and stores the report as plain text in the file "C:\some\path\to\your\file.txt".
The script tries to identify the failover cluster that the local host belongs to and report on all nodes. Should there be no cluster it will switch to LocalHostInventory mode and only report on the local host.

 
.NOTES
- Set your PowerShell Execution Policy to "RemoteSigned" at least. Depending on where your copy is stored you might need to set it to "Unrestricted".
  Example: 'Set-ExecutionPolicy RemoteSigned'
- Run the script like this in the powershell commandshell: ./Get-HyperVInventory.ps1 [-output <string>] [-mode <string>] [-format <string>] [-noview <boolean>]
- Run the script locally on the Hyper-V host server that you want to report on (or on one of the cluster hosts of the cluster you want to document).
- If you encounter any bugs, or have got an idea on how to improve the script, please report to cju@michael-wessel.de

 
.LINK
http://www.michael-wessel.de 
 
#>

########################################################
#                Get-HyperVInventory                   #
# version: v2.4-170224                                 #
# authors:  Christopher Junker, Nils Kaczenski,        #
#           Sascha Loth (external)                     #
# company: Michael Wessel Informationstechnologie GmbH #
# mail:    windows@michael-wessel.de                   #
# phone:   0511 260 911 0                              #
# date:    13|01|2016                                  #
########################################################


# Getting Parameters 
[cmdletbinding()]
param(
[Parameter(Mandatory=$false)]
[string]$output,

[Parameter(Mandatory=$false)]
[ValidateSet('ClusterFullInventory','LocalHostInventory','RemoteHostInventory','ClusterOnlyInventory','LocalHostOnlyInventory','RemoteHostOnlyInventory','VMInventoryCluster','VMInventoryLocalHost','VMInventoryRemoteHost','SingleVMInventory')]
[string]$mode,

[Parameter(Mandatory=$false)]
[ValidateSet('HTML','TXT')]
[string]$format,

[Parameter(Mandatory=$false)]
[bool]$noview,

[Parameter(Mandatory=$false)]
[string]$remoteHost,

[Parameter(Mandatory=$false)]
[string]$VMName
)



############################################################################################################
function Get-ReportInfo
{
   param
   (
     [Object]
     $mode
   )

'Getting report info ...'
$time = Get-Date
Write-Header 1 'Hyper-V Environment Inventory'
Write-Header 2 "Report mode: $mode"
Write-Line 'Created on' ($time.DateTime)
Write-Line 'Created by' (whoami.exe)
Write-Line 'Local server' $LocalHostName
Write-Line 'Script folder' ($PSScriptRoot)
Write-Line 'Script version' ('<a href="https://gallery.technet.microsoft.com/Get-HyperVInventory-Create-2c368c50" target="_blank">' + $ScriptVersion + '</a>')
Write-Separator
}

############################################################################################################
function Get-ClusterInfo()
{
'Getting cluster info ...'
# get cluster core data
$cluster = Get-Cluster
Write-Header 1 'General cluster information'
Write-Line 'Cluster Name' $cluster.Name

# get cluster IP address
$clusterGroup = Get-ClusterGroup | Where-Object { $_.GroupType -eq 'Cluster' }
$clusterIP = Get-ClusterResource | Where-Object { $_.ResourceType -eq 'IP Address' -and $_.OwnerGroup -eq $clusterGroup } | Get-ClusterParameter Address  
$clusterSubnet = Get-ClusterResource | Where-Object { $_.ResourceType -eq 'IP Address' -and $_.OwnerGroup -eq $clusterGroup } | Get-ClusterParameter SubnetMask
Write-Line 'Cluster IP address' ($clusterIP.Value + ' (' + $clusterSubnet.Value + ')')
Write-Separator

# get quorum config and resource
$quorum = Get-ClusterQuorum | Select-Object QuorumResource 
Write-Line 'Quorum resource name' ($quorum.QuorumResource.Name)
$quorumType = Get-ClusterQuorum | Select-Object QuorumType 
Write-Line 'Quorum type' ($quorumType.QuorumType)
Write-Separator

# check for S2D presence
if ((Get-Command Get-ClusterStorageSpacesDirect -ErrorAction SilentlyContinue) -ne $null) {
  $S2D = (Get-ClusterStorageSpacesDirect -ErrorAction SilentlyContinue)
  if ($S2D -ne $null) {
    Write-Line 'Storage Spaces Direct active' ($S2D.State)
    Write-Line 'S2D Name' ($S2D.Name)
    Write-Line 'S2D Cache Mode HDD' ($S2D.CacheModeHDD)
    Write-Line 'S2D Cache Mode SSD' ($S2D.CacheModeSSD)
    Write-Line 'S2D Cache Device Model' ($S2D.CacheDeviceModel)
    Write-Line 'S2D Cache Metadata Reserve Bytes' ($S2D.S2DCacheMetadataReserveBytes)
    Write-Line 'S2D Cache Page Size KBytes' ($S2D.CachePageSizeKBytes)
    Write-Separator
  }
}

# get cluster nodes
$clusterNodes = (Get-ClusterNode | Sort-Object ID)
Write-Line 'Number of cluster nodes' ($clusterNodes.Count)
Write-Separator
foreach ($clusterNode in $clusterNodes)
{
  Write-Line 'Node ID ' ($clusterNode.ID) 
  Write-Line 'Node name' ($clusterNode.Name)
  Write-Line 'Node weight' ($clusterNode.NodeWeight)
  Write-Separator
}

# get cluster networks
Write-Header 3 'Cluster networks'
$clusterNetworks = (Get-ClusterNetwork | Sort-Object Name)
Write-Line 'Number of cluster networks' ($clusterNetworks.Count)
Write-Separator
foreach($clusterNetwork in $clusterNetworks)
{
    Write-Line 'Cluster network name' ($clusterNetwork.Name)
    Switch ($clusterNetwork.Role)
    {
      0 {$CNRole = 'No cluster communication'}
      1 {$CNRole = 'Cluster communication only'}
      3 {$CNRole = 'Cluster and client communication'}
      default {$CNRole = 'unknown'}
    }
    Write-Line 'Network role' ([string]$clusterNetwork.Role + ' (' + $CNRole + ')')
    $CNAddress = $clusterNetwork.Address
    if ($clusterNetwork.Addressmask -ne $null) 
    {
      $CNAddress = $CNAddress + ' (' + $clusterNetwork.Addressmask + ')'
    }
    if ($CNAddress -eq $null) 
    { 
      $CNAddress = 'not set'
    }
    Write-Line 'Address' $CNAddress
    if($clusterNetwork.Ipv4Addresses.Length -ne 0 -or $clusterNetwork.Ipv4Addresses -ne {}) 
    {
        Write-Line 'All IPv4 address(es)' ($clusterNetwork.Ipv4Addresses)
    }
    else
    {
        Write-Line 'IPv4 address(es)' 'not set'
    }

        if($clusterNetwork.Ipv6Addresses.Length -ne 0 -or $clusterNetwork.Ipv6Addresses -ne {}) 
    {
        Write-Line 'All IPv6 address(es)' ($clusterNetwork.Ipv6Addresses)
    }
    else
    {
        Write-Line 'IPv6 address(es)' 'not set'
    }
    Write-Separator
}

# get Live Migration networks
Write-Header 4 'Live Migration networks'
$LMNetworks = (Get-VMMigrationNetwork -ComputerName $cluster.Name -ErrorAction SilentlyContinue | Sort-Object Priority -Descending)
foreach ($LMN in $LMNetworks)
{
  Write-Line ('Network ' + $LMN.Subnet) ('Priority ' + [string]$LMN.Priority)
}

Write-Separator

# get cluster disks (non-CSV first, then CSV)
Write-Header 3 'Cluster disks'
$ClusterDisks =  (Get-ClusterResource | Where-Object {$_.ResourceType -eq 'Physical Disk'} | Sort-Object OwnerGroup,Name)
Write-Line 'Number of cluster disks' ($ClusterDisks.Count)
Write-Separator
foreach ($Disk in $ClusterDisks)
{
  Write-Line 'Owner group' ($Disk.OwnerGroup)
  Write-Line 'Cluster disk' ($Disk.Name)
  Write-Line 'Owner node' ($Disk.OwnerNode)
  Write-Line 'State' ($Disk.State)
  Write-Separator
}

# get CSVs
Write-Header 4 'Cluster Shared Volumes'
$clusterSharedVolume = (Get-ClusterSharedVolume -Cluster $cluster | Sort-Object Name)
Write-Line 'Number of CSVs' ($clusterSharedVolume.Count)
Write-Separator
foreach ($CSV in $clusterSharedVolume)
{
  Write-Line 'CSV name' ($CSV.Name)
  Write-Line 'CSV owner' ($CSV.OwnerNode)
  foreach ($CSVInfo in $CSV.SharedVolumeInfo)
  {
    Write-Line 'CSV volume' ($CSVInfo.FriendlyVolumeName)
  }
  if (Get-Command Get-ClusterSharedVolumeState -ErrorAction SilentlyContinue) 
  {
    # Get-ClusterSharedVolumeState does not exist in 2012
    $CSVVolPath = (Get-ClusterSharedVolumeState -Name $CSV.Name -Cluster $cluster).VolumeName
    $CSVVolume = Get-Volume -Path $CSVVolPath
    $VolName = $CSVVolPath -replace '\\', '\\'
    $wql = "SELECT Blocksize FROM Win32_Volume WHERE DeviceID='$VolName'"
    $BlockSize = (Get-WmiObject -Query $wql -ComputerName $clusterNode).Blocksize
    Write-Line 'CSV disk cluster size' ('{0:N2}' -f($BlockSize / 1KB) + ' KB')
    Write-Line 'CSV size' ('{0:N2}' -f($CSVVolume.Size / 1GB) + ' GB')
    Write-Line 'CSV free space' ('{0:N2}' -f($CSVVolume.SizeRemaining / 1GB) + ' GB')
    Write-Separator
  }
  else 
  {
    Write-Line 'CSV size and free space' 'not determined'
    Write-Separator
  }
}

Write-Header 3 'Cluster roles'
# get clustered VMs 
Write-Header 4 'VMs on cluster'
$arrClusterVMs = (Get-ClusterGroup -Cluster $cluster | Where-Object {$_.GroupType -eq 'VirtualMachine'} | Sort-Object Name)
if ($arrClusterVMs.length -ne 0)
{
  Write-Line 'Number of cluster VMs' ($arrClusterVMs.length)
  Write-Separator
  foreach ($clusterVM in $arrClusterVMs)
  {
    Write-Line '  Name' ($clusterVM.Name + ' (' + $clusterVM.State + ')')
    Write-Line '  Owner' ($clusterVM.OwnerNode)
    Write-Separator
  }
} else {
    Write-Line $null '  none'
    Write-Separator
}

# get additional cluster roles
Write-Header 4 'Non-VM cluster groups'
$arrRolesToIgnore = 'VirtualMachine', 'Cluster', 'AvailableStorage'
$arrClusterGroups = (Get-ClusterGroup -Cluster $cluster | Where-Object {$arrRolesToIgnore -notcontains $_.GroupType} | Sort-Object Name)
if ($arrClusterGroups.length -ne 0)
{
  Write-Line 'Number of cluster groups' ($arrClusterGroups.length)
  Write-Separator
  foreach ($clusterRole in $arrClusterGroups)
  {
    Write-Line '  Name' ($clusterRole.Name + ' (' + $clusterRole.State + ')')
    Write-Line '  Type' ($clusterRole.GroupType)
    Write-Line '  Owner' ($clusterRole.OwnerNode)
    Write-Separator
  }
} else {
    Write-Line $null '  none'
    Write-Separator
}

# determine CAU availability
$CAU = (Get-ClusterResource -Cluster $cluster | Where-Object { $_.ResourceType -eq 'ClusterAwareUpdatingResource' })
if ($CAU -ne $null) {
  Write-Line 'Cluster-Aware Updating for self-updates' ($CAU.State)
  Write-Line 'CAU name' ($CAU.OwnerGroup)
} else {
  Write-Line 'Cluster-Aware Updating for self-updates' 'not installed'
}

# List Cluster Group Sets, if any
if ((Get-Command Get-ClusterGroupSet -ErrorAction SilentlyContinue) -ne $null) {
  $CGSet = (Get-ClusterGroupSet)
  if ($CGSet -ne $null) {
    Write-Separator
    Write-Header 4 'Cluster Group Sets'
    foreach ($Set in $CGSet) {
      Write-Line 'Cluster Group Set Name' $Set.Name
      Write-Line 'Trigger' $Set.StartupDelayTrigger
      Write-Line 'Delay' $Set.StartupDelay
      Write-Line 'Members' $Set.GroupNames
      Write-Line 'Providers' $Set.Providers
      Write-Separator
    }
  }
}
}

############################################################################################################
function Get-HostOSInfo
{
   param
   (
     [Object]
     $clusterNode
   )

"Getting host $clusterNode OS info ..."
#takes $clusterNode to give it as -ComputerName

Write-Separator
Write-Header 1 "Software Information for host $clusterNode"
$hostOS = Get-WMIObject Win32_Operatingsystem -ComputerName $clusterNode
Write-Line 'Host OS' ($hostOS.Caption)
$OSBuildNumber = ([int]$hostOS.BuildNumber)
Write-Line 'Host OS version' ($hostOS.GetPropertyValue('Version') + ', Build ' + $OSBuildNumber)
Write-Line 'Service Pack' ([string]$hostOS.ServicePackMajorVersion + '.' + [string]$hostOS.ServicePackMinorVersion)
Write-Line 'OS installation date' (([WMI]'').ConvertToDateTime($hostOS.InstallDate))
Write-Line 'PowerShell version' ([string]$PSVersionTable.PSVersion)
$PowerPlanActive = (Get-WmiObject -Namespace root\cimv2\power -Class win32_PowerPlan -ComputerName $clusterNode | Where-Object {$_.IsActive -eq $true})
Write-Line 'PowerPlan (active)' $PowerPlanActive.ElementName
Write-Line 'Number of updates installed' ((Get-HotFix -ComputerName $clusterNode).count)

# check for critical update KB3046359 (guest breakout vulnerability, WS 2012 R2)
if (($OSBuildNumber -eq 9600) -and ((Check-SpecificHotFix -HotFixId 'KB3046359' -ClusterNode $clusterNode) -eq $false))
{
  Write-Line 'WARNING' 'Hotfix KB3046359 is not present!'
} 

# check for critical update KB3046339 (guest breakout vulnerability, WS 2012)
if (($OSBuildNumber -eq 9200) -and ((Check-SpecificHotFix -HotFixId 'KB3046339' -ClusterNode $clusterNode) -eq $false))
{
  Write-Line 'WARNING' 'Hotfix KB3046339 is not present!'
} 

Write-Separator

# no server roles on a client
if ($IsClient -eq $false)
{
  $hostRoles = Get-WindowsFeature -ComputerName $clusterNode | Where-Object {$_.Installed -eq $true } 
  Write-Header 3 ('Server roles installed on: ' + $clusterNode)
  Write-Line 'Number of roles installed' ($hostRoles.Count)
  foreach ($Role in $hostRoles)
  {
    # $RoleDisplay = '  ' * $Role.Depth + $Role.DisplayName
    Write-LineIndent $null $Role.DisplayName ($Role.Depth - 1)
  }
}
}

############################################################################################################
function Get-HostGeneralInfo
{
   param
   (
     [Object]
     $clusterNode
   )

"Getting host $clusterNode info ..."
#takes $clusternode to give it as -ComputerName
Write-Separator
Write-Header 1 "Hyper-V configuration information for host $clusterNode"
# evaluating name and members of Hyper-V Administrators (well-know SID S-1-5-32-578)
# this takes quite some time, seems we cannot make it faster
'  enumerating Hyper-V Administrators will take a moment ...'
$HVAdmins=Get-WmiObject -Class Win32_Group -computername $clusterNode -Filter "SID='S-1-5-32-578' AND LocalAccount='True'" -errorAction 'Stop'
$HVAMembers = ($HVAdmins.GetRelated().Caption | Where-Object {$_ -ne $null} | Sort-Object )
$HVAName = $HVAdmins.Name
Write-Line 'Hyper-V Administrators group name' $HVAName
Write-Line "$HVAName group members" ($HVAMembers.Count)
#if ($HVAMembers.Count -eq 0)
#{
#  Write-Line $null '  none'
#} else {
#  foreach($member in $HVAMembers)
#  {
#    Write-Line $null ('  ' + $member)
#  }
#}
if ($HVAMembers.Count -ne 0)
{
  foreach($member in $HVAMembers)
  {
    Write-Line $null ('  ' + $member)
  }
}

'  ... done'
# continue with the usual stuff, this is much faster
$hostInfo = Get-VMHost -ComputerName $clusterNode
Write-Line 'Default VM configuration path' ($hostInfo.VirtualMachinePath)
Write-Line 'Default VM virtual hard disk path' ($hostInfo.VirtualHardDiskPath)
Write-Line 'Enhanced Session Mode' ($hostInfo.EnableEnhancedSessionMode)
Write-Line 'NUMA spanning enabled' ($hostInfo.NumaSpanningEnabled)
Write-Line 'MAC address pool start' ($hostInfo.MacAddressMinimum)
Write-Line 'MAC address pool end' ($hostInfo.MacAddressMaximum)
Write-Line 'Live Migration enabled' ($hostInfo.VirtualMachineMigrationEnabled)
Write-Line 'Live Migration concurrent' ($hostInfo.MaximumVirtualMachineMigrations)
Write-Line 'Storage Live Migration concurrent' ($hostInfo.MaximumStorageMigrations)
Write-Line 'Live Migration authentication' ($hostInfo.VirtualMachineMigrationAuthenticationType)
Write-Line 'Live Migration method' ($hostInfo.VirtualMachineMigrationPerformanceOption)
Write-Line 'Live Migration over any network' ($hostInfo.UseAnyNetworkForMigration)
$ReplicationHost = Get-VMReplicationServer -ComputerName $clusterNode -ErrorAction SilentlyContinue
if ($ReplicationHost -ne $null)
{
  Write-Line 'Replication enabled' ($ReplicationHost.ReplicationEnabled)
  Write-Line 'Replication allowed from any server' ($ReplicationHost.ReplicationAllowedFromAnyServer)
  Write-Line 'Replication authentication type' ($ReplicationHost.AuthType)
  Write-Line 'Replication data default storage path' ($ReplicationHost.DefaultStorageLocation)
}
Write-Separator
}

############################################################################################################
function Get-HostHWInfo($clusterNode)
{
"Getting host $clusterNode hardware info ..."
#takes $clusternode to give it as -ComputerName
Write-Separator
Write-Header 1 "Hardware Information for host $clusterNode"
$hostHW = Get-WmiObject Win32_ComputerSystem -ComputerName $clusterNode 
$hostEnclosure = Get-WmiObject Win32_SystemEnclosure -ComputerName $clusterNode 
Write-Line 'Model' ($hostHW.GetPropertyValue('Model'))
Write-Line 'Manufacturer' ($hostHW.GetPropertyValue('Manufacturer'))
Write-Line 'Serial number' ($hostEnclosure.GetPropertyValue('SerialNumber'))
Write-Line 'Domain' ($hostHW.GetPropertyValue('Domain'))
Write-Line 'Total RAM' ('{0:N0}' -f($hostHW.TotalPhysicalMemory / 1MB)  + ' MB')
Write-Separator
}


############################################################################################################
function Get-HostCPUInfo($clusterNode)
{
"Getting host $clusterNode CPU info ..."
#takes $clusterNode to give it as -ComputerName
$vProcessors = (Get-WmiObject Win32_Processor -ComputerName $clusterNode | Sort-Object DeviceID)
$hostHW = Get-WmiObject Win32_ComputerSystem -ComputerName $clusterNode 
foreach ($CPU in $vProcessors)
{
  Write-Line ('CPU ' + [string]$CPU.DeviceID) ($CPU.Name)
}
Write-Line 'Max. CPU speed' ([string]($vProcessors.MaxClockSpeed[0] / 1000) + ' GHz')

# processor count detection
# based on http://darrylcauldwell.com/is-hyperthreading-enabled/
# the original source needed some corrections!
$vLogicalCPUs = 0
$vPhysicalCPUs = 0
$vCPUCores = 0
$vSocketDesignation = 0
$vIsHyperThreaded = -1
$vPhysicalCPUs = $vProcessors.count
# if there is only one CPU there is no count, so we set 1 in that case
if ($vPhysicalCPUs -eq $null) { $vPhysicalCPUs = 1 }
$vLogicalCPUs = $($vProcessors|measure-object NumberOfLogicalProcessors -sum).Sum
$vCores = $($vProcessors|measure-object NumberOfCores -sum).Sum

# Additional code can be written here to input the data below into a database
# "Logical CPUs: {0}; Physical CPUs: {1}; Number of Cores: {2}" -f $vLogicalCPUs,$vPhysicalCPUs,$vCores
Write-Line 'Physical CPUs' $vPhysicalCPUs
Write-Line 'Cores' $vCores
Write-Line 'Logical CPUs' $vLogicalCPUs
if ($vLogicalCPUs -gt $vCores)
{
  Write-Line 'Hyperthreading' 'Active'
}
else
{
  Write-Line 'Hyperthreading' 'Inactive'
}
Write-Separator
}

############################################################################################################
function Get-HostStorageInfo
{
  param
  (
  [Parameter(Mandatory=$false,Position=1)]
  $ClusterNode,

  [Parameter(Mandatory=$false,Position=2)]
  $Cim
  )

"Getting host $clusterNode storage info ..."
Write-Header 2 'Storage information'
if ($cim -eq $null)
{
  $iSCSIConnections = (Get-IscsiConnection)
}
else
{
  $iSCSIConnections = (Get-IscsiConnection -CimSession $cim)
}
if ($iSCSIConnections -ne $null)
{
  Write-Header 4 'iSCSI connections'  
  # write number only if there are multiple elements
  if ($iSCSIConnections.Count)
  {
    Write-Line 'Number of iSCSI connections' ($iSCSIConnections.Count)
  }
  Write-Separator
  foreach ($iSCSIConnection in $iSCSIConnections)
  {
    Write-Line 'iSCSI Connection ID' ($iSCSIConnection.ConnectionIdentifier)
    Write-Line 'iSCSI target address' (($iSCSIConnection.TargetAddress) + ':' + ($iSCSIConnection.TargetPortNumber))
    foreach ($iSCSISession in (Get-IscsiSession -IscsiConnection $iSCSIConnection -CimSession $cim))
    {
    Write-Line 'iSCSI Session ID' ($iSCSISession.SessionIdentifier)
    Write-Line 'iSCSI target node address' ($iSCSISession.TargetNodeAddress)
    }
    Write-Separator
  }
}

$vSANs = (Get-VMSan -ComputerName $clusterNode -ErrorAction SilentlyContinue | Sort-Object Name)
if ($vSANs -ne $null) {
  Write-Header 4 'Fibre Channel vSAN configuration'
  Write-Line 'Number of vSANs' ($vSANs.Count)
  foreach($vSANs in $vSANs)
  {
    Write-Separator
    Write-Line 'vSAN name' ($vSANs.name)
    Write-Line 'vSAN PortWWN' ($vSANs.HBAs.NodeAddress)

  }
  Write-Separator
}

Write-Header 4 'Host drives'
if ($cim -eq $null)
{
  $hostDrives = (Get-Disk | Sort-Object FriendlyName)
}
else
{
  $hostDrives = (Get-Disk -CimSession $cim | Sort-Object FriendlyName)
}
Write-Line 'Number of drives' ($hostDrives.Count)
Write-Separator
foreach ($hostDrive in $hostDrives)
{
    Write-Line 'Drive name' ($hostDrive.FriendlyName)
    Write-Line 'Status ' ($hostDrive.OperationalStatus)
    Write-Line 'Disk number' ($hostDrive.Number)
    Write-Line 'Boot drive' ($hostDrive.IsBoot)
    Write-Line 'Bus type' ($hostDrive.BusType)
    Write-Line 'Provisioning type' ($hostDrive.ProvisioningType)
    Write-Line 'Partition style' ($hostDrive.PartitionStyle)
    Write-Line 'Number of partitions' ($hostDrive.NumberOfPartitions)
    Write-Line 'Size' ('{0:N2}' -f($hostDrive.Size / 1GB) + ' GB')
    Write-Separator
}

Write-header 4 'Host volumes'
#$cim = New-CimSession -ComputerName $clusterNode
if ($cim -eq $null)
{
  $hostVolumes = (Get-Volume | Sort-Object DriveLetter,FileSystemLabel)
}
else
{
  $hostVolumes = (Get-Volume -CimSession $cim | Sort-Object DriveLetter,FileSystemLabel)
}
Write-Line 'Number of volumes' ($hostVolumes.Count)
Write-Separator
foreach ($hostVolume in $hostVolumes)
{
    Write-Line 'Volume' ($hostVolume.DriveLetter + ' (' + $hostVolume.FileSystemLabel + ')')
    # map volume to drive and partition
    $Parts = Get-Partition | Where-Object { $_.AccessPaths -eq $hostVolume.Path} 
		foreach ($part in $Parts)
		{
		  Write-Line 'Located on' ('Disk ' + [string]$part.DiskNumber + ', Partition ' + [string]$part.PartitionNumber)
		}
    Write-Line 'Drive Type' ($hostVolume.DriveType)
    Write-Line 'File System' ($hostVolume.FileSystem)
    # get block size
    $VolName = $hostVolume.ObjectID -replace '\\', '\\'
    $wql = "SELECT Blocksize FROM Win32_Volume WHERE DeviceID='$VolName'"
    $BlockSize = (Get-WmiObject -Query $wql -ComputerName $ClusterNode).Blocksize
    Write-Line 'Disk cluster size'  ('{0:N2}' -f($BlockSize / 1KB) + ' KB')
    Write-Line 'Size' ('{0:N2}' -f($hostVolume.Size / 1GB) + ' GB')
    Write-Line 'Free space' ('{0:N2}' -f($hostVolume.SizeRemaining / 1GB) + ' GB')
    Write-Separator
}
}

############################################################################################################
function Get-HostNICInfo
{
  param
  (
  [Parameter(Mandatory=$false,Position=1)]
  $ClusterNode,

  [Parameter(Mandatory=$false,Position=2)]
  $Cim
  )


"Getting host $clusterNode network info ..."
Write-Separator
Write-Header 2 'Host networks'
#$cim = New-CimSession -ComputerName $clusterNode
if ($cim -eq $null)
{
  $hostNetworks = (Get-NetAdapter | Sort-Object Name)
}
else
{
  $hostNetworks = (Get-NetAdapter -CimSession $cim | Sort-Object Name)
}
Write-Line 'Number of networks' ($hostNetworks.Count)
Write-Separator
foreach($hostNetwork in $hostNetworks)
{
    Write-Line 'Network name' ($hostNetwork.Name)
    Write-Line 'Interface name' ($hostNetwork.InterfaceDescription)
    if ($hostNetwork.Virtual -eq $true) { Write-Line 'Virtual network adapter' $true }
    Write-Line 'Link Speed' ($hostNetwork.LinkSpeed + ' (' + $hostNetwork.MediaConnectionState + ')')
    Write-Line 'Driver' ($hostNetwork.DriverName + ' (' + $hostNetwork.DriverInformation + ')')
    Write-Line 'MAC address' ($hostNetwork.MacAddress)
    Write-Line 'MTU Size' ($hostNetwork.ActiveMaximumTransmissionUnit)
    if ($cim -eq $null)
    {
      if ((Get-NetAdapterBinding -Name $hostNetwork.Name -ComponentID 'vms_pp').Enabled) { Write-Line 'vSwitch protocol' 'active' }
      if ((Get-NetAdapterBinding -Name $hostNetwork.Name -ComponentID 'ms_implat').Enabled) { Write-Line 'Windows NIC teaming protocol' 'active' }
      $Bindings = (Get-NetAdapterBinding -Name $hostNetwork.Name | Where-Object Enabled -eq $true | Sort-Object DisplayName)
    }
    else
    {
      if ((Get-NetAdapterBinding -CimSession $cim -Name $hostNetwork.Name -ComponentID 'vms_pp').Enabled) { Write-Line 'vSwitch protocol' 'active' }
      if ((Get-NetAdapterBinding -CimSession $cim -Name $hostNetwork.Name -ComponentID 'ms_implat').Enabled) { Write-Line 'Windows NIC teaming protocol' 'active' }
      $Bindings = (Get-NetAdapterBinding -CimSession $cim -Name $hostNetwork.Name | Where-Object Enabled -eq $true | Sort-Object DisplayName)
    }
    if ($Bindings -eq $null)
    {
      $ProtBind = 'none'
    }
    else
    {
      $ProtBind =@()
      foreach ($Binding in $Bindings)
      {
        $ProtBind += ,$Binding.DisplayName 
      }
    }
    Write-Line 'Protocol bindings' $ProtBind
    if ($cim -eq $null)
    {
      $NICIP = (Get-NetIPAddress -InterfaceIndex $hostNetwork.InterfaceIndex -ErrorAction SilentlyContinue | Sort-Object IPAddress)
      $NICGate = (Get-NetRoute -InterfaceIndex $hostNetwork.InterfaceIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
      $NICDNS = (Get-DnsClientServerAddress -InterfaceIndex $hostNetwork.InterfaceIndex -ErrorAction SilentlyContinue)
    }
    else
    {
      $NICIP = (Get-NetIPAddress -CimSession $cim -InterfaceIndex $hostNetwork.InterfaceIndex -ErrorAction SilentlyContinue | Sort-Object IPAddress)
      $NICGate = (Get-NetRoute -CimSession $cim -InterfaceIndex $hostNetwork.InterfaceIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
      $NICDNS = (Get-DnsClientServerAddress -CimSession $cim -InterfaceIndex $hostNetwork.InterfaceIndex -ErrorAction SilentlyContinue)
    }
    if($NICIP -ne $null) {
        foreach($myIP in $NICIP)
        {
            Write-Line 'IP address' ($myIP.IPAddress + '/' + $myIP.PrefixLength)
        }
    } else {
        Write-Line 'IP address' 'none assigned'
    }
    if($NICGate -ne $null) {
        Write-Line 'Default gateway' ($NICGate.NextHop)
    } else {
        Write-Line 'Default gateway' 'none assigned'
    }
    if($NICDNS -ne $null) {
        Write-Line 'DNS server(s)' ($NICDNS.ServerAddresses)
    } else {
        Write-Line 'DNS server' 'none assigned'
    }
    Write-Separator
}
### vNICs for Management OS
Write-Header 4 'Virtual network adapters in the Management OS'
$vmNetCards = (Get-VMNetworkAdapter -ManagementOS -ComputerName $clusterNode | Sort-Object Name)
if ($vmNetCards -eq $null)
{
  Write-Line $null 'none'
  Write-Separator
} else {
  Write-Line 'Number of adapters' ($vmNetCards.Count)
  Write-Separator
  ForEach($vmNetCard in $vmNetCards)
  {
    Write-Line 'Virtual network adapter' ($vmNetCard.Name)
    Write-Line 'Legacy adapter' ($vmNetCard.IsLegacy)
    Write-Line 'vNIC ID' ($vmNetCard.ID)
    Write-Line 'Connected' ($vmNetCard.Connected)

    #vmNetCard Switch
    if($vmNetCard.SwitchName.Length -ne 0)
    {
      Write-Line 'vSwitch connected' ($vmNetCard.SwitchName)
    }
    else
    {
      Write-Line 'vSwitch connected' 'none'
    }

    #vmNetCard MACAddress
    Write-Line 'Dynamic MAC address' ($vmNetCard.DynamicMacAddressEnabled)
    if($vmNetCard.MacAddress.Length -ne 0)
    {
      Write-Line 'MAC address' ($vmNetCard.MacAddress)
    }
    else
    {
      Write-Line 'MAC address' 'not assigned'
    }

    #vmNetCard IPAddress
    $vmnetCardIPs = $vmNetCard.IPAddresses
    if($vmNetCard.IPAddresses.Length -ne 0)
    {
      ForEach($vmnetCardIP in $vmnetCardIPs)
      {
        Write-Line 'IP address' $vmNetCardIP
      }
    }
    else
    {
      Write-Line 'IP address' 'not assigned'
    }
    # special features (could be extended in future versions)
    Write-Line 'DHCP Guard' ($vmNetCard.DhcpGuard)
    Write-Line 'Router Guard' ($vmNetCard.RouterGuard)
    Write-Line 'VLAN setting' ('mode ' + $vmNetCard.VlanSetting.OperationMode + ', VLAN ID ' + $vmNetCard.VlanSetting.AccessVlanId)
    if ($vmNetCard.BandwidthSetting.MinimumBandwidthAbsolute -ne $null -or $vmNetCard.BandwidthSetting.MaximumBandwidth -ne $null)
    {
      # Bandwidth settings say they use Mbit but they only multiply the GUI value by a million ...
      Write-Line 'Bandwidth setting' ('min Mbits ' + ($vmNetCard.BandwidthSetting.MinimumBandwidthAbsolute)/1000000 + ', max Mbits ' + ($vmNetCard.BandwidthSetting.MaximumBandwidth)/1000000)
      Write-Line 'Bandwidth minimum weight' ($vmNetCard.BandwidthSetting.MinimumBandwidthWeight)
      Write-Line 'Bandwidth percentage' ($vmNetCard.BandwidthPercentage)
    }
    Write-Separator
  }
}

### end vNICS

Write-header 4 'Network adapter teaming in the Management OS'
if ($cim -eq $null)
{
  $NICTeams = (Get-NetLbfoTeam | Sort-Object Name)
}
else
{
  $NICTeams = (Get-NetLbfoTeam -CimSession $cim  | Sort-Object Name)
}
if ($NICTeams -eq $null)
{
  Write-Line 'NIC teaming' 'inactive'
  Write-Separator
} else {
  foreach ($NICTeam in $NICTeams)
  {
    Write-Line 'NIC team name' ($NICTeam.Name)
    Write-Line 'NIC team network name' ($NICTeam.TeamNics)
    Write-Line 'Teaming mode' ($NICTeam.TeamingMode)
    Write-Line 'Load balancing' ($NICTeam.LoadBalancingAlgorithm)
    if ($cim -eq $null)
    {
      $NICTeamMembers = (Get-NetLbfoTeamMember -Team $NICTeam.Name | Sort-Object Name)
    }
    else
    {
      $NICTeamMembers = (Get-NetLbfoTeamMember -Team $NICTeam.Name -CimSession $cim | Sort-Object Name)
    }
    foreach ($NICTeamMember in $NICTeamMembers)
    {
      Write-Line 'Team member' ($NICTeamMember.Name + ' (' + $NICTeamMember.InterfaceDescription + ')')
    }
    if ($cim -eq $null)
    {
      $NICTeamNICs = Get-NetLbfoTeamNic -Team $NICTeam.Name
    }
    else
    {
      $NICTeamNICs = Get-NetLbfoTeamNic -Team $NICTeam.Name -CimSession $cim
    }
    foreach ($NICTeamNIC in $NICTeamNICs)
    {
      Write-Line 'Team NIC' ($NICTeam.Name + ' (' + $NICTeamNIC.InterfaceDescription + ')')
      Write-Line 'Team NIC VLAN' ($NICTeamNIC.VlanID)
    }
  Write-Separator
  }
}

Write-Header 4 'VMQueue ability'
if ($cim -eq $null)
{
  $VMQNICs = (Get-NetAdapterVmq | Sort-Object Name)
}
else
{
  $VMQNICs = (Get-NetAdapterVmq -CimSession $cim | Sort-Object Name)
}
if ($VMQNICs -eq $null)
{
  Write-Line 'Network adapters capable of VMQueue' 'none'
  Write-Separator
} else {
  foreach ($VMQ in $VMQNICs)
  {
    Write-Line 'Network adapter' ($VMQ.Name)
    Write-Line 'Interface name' ($VMQ.InterfaceDescription)
    Write-Line 'VMQueue enabled' ($VMQ.Enabled)
    Write-Separator
  }
}
}

############################################################################################################
function Get-HostVMInfo
{
   param
   (
     [Object]
     $vms,

     [Object]
     $clusterNode
   )

"Getting VM info for host $clusterNode ..."
Write-Separator
    
Write-header 2 ('VM list for host ' + $clusterNode)
Write-Line 'Number of VMs' ($vms.Count)
$VMRAM = 0
$VMCPU = 0
foreach ($vm in $vms)
{
  Write-Line 'VM name' ($vm.VMName)
  $VMRAM = $VMRAM + $vm.MemoryStartup
  if ($vm.DynamicMemoryEnabled) {
    $VMRAMMax = $VMRAMMax + $vm.MemoryMaximum
  }
  $VMCPU = $VMCPU + $vm.ProcessorCount
}

# add node values to global counters
$script:GlobalVMRAM = $script:GlobalVMRAM + $VMRAM
$script:GlobalVMRAMMax = $script:GlobalVMRAMMax + $VMRAMMax
$script:GlobalvCPU = $script:GlobalvCPU + $VMCPU

Write-Separator
Write-Line 'Sum of memory in GB (static and startup)' ('{0:N0}' -f($VMRAM/1GB))
Write-Line 'Sum of dynamic memory maximum in GB' ('{0:N0}' -f($VMRAMMax/1GB))
Write-Line 'Sum of vCPUs assigned' $VMCPU

if ((Get-Command Get-VMGroup -ErrorAction SilentlyContinue) -ne $null) {
  Write-Separator
  Write-Header 3 'VM Groups'
  $VMGroupMgmt = (Get-VMGroup | Where-Object {$_.GroupType -eq 'ManagementCollectionType'})
  foreach ($Group in $VMGroupMgmt) {
    Write-Line 'VM Management Collection' $Group.Name
    Write-Line 'Instance ID' $Group.InstanceId
    Write-Line 'VM Group members' $Group.VMGroupMembers.Count
    foreach ($Member in $Group.VMGroupMembers) {
      Write-Line $null ($Member.Name + ' (' + $Member.InstanceId + ')')
    }
    Write-Separator
  }
  $VMGroupVM = (Get-VMGroup | Where-Object {$_.GroupType -eq 'VMCollectionType'})
  foreach ($Group in $VMGroupVM) {
    Write-Line 'VM Collection' $Group.Name
    Write-Line 'Instance ID' $Group.InstanceId
    Write-Line 'VM members' $Group.VMMembers.Count
    foreach ($Member in $Group.VMMembers) {
      Write-Line $null ($Member.Name)
    }
    Write-Separator
  }

}
}

############################################################################################################
function Get-HostvSwitchInfo
{
  param
  (
  [Parameter(Mandatory=$false,Position=1)]
  $vm,

  [Parameter(Mandatory=$false,Position=2)]
  $ClusterNode,

  [Parameter(Mandatory=$false,Position=3)]
  $Cim
  )

"Getting host $clusterNode vSwitch info ..."
$vSwitches = (Get-VMSwitch -ComputerName $clusterNode | Sort-Object Name)
Write-Separator
Write-Header 1 'vSwitch configuration'
Write-Line 'Number of vSwitches' ($vSwitches.Count)

foreach($vSwitch in $vSwitches)
{
  $vSwitchExtension = (Get-VMSwitchExtension -VMSwitchName $vSwitch.Name | Sort-Object Name)
  Write-Separator
  Write-Line 'vSwitch name' ($vSwitch.Name)
  Write-Line 'vSwitch notes' ($vSwitch.Notes)
  Write-Line 'vSwitch type' ($vSwitch.SwitchType)
  Write-Line 'Bandwidth reservation mode' ($vSwitch.BandwidthReservationMode)
  Write-Line 'Bandwidth default percentage' ($vSwitch.BandwidthPercentage)
  # Bandwidth settings say they use Mbit but they only multiply the GUI value by a million ...
  Write-Line 'Bandwidth default minimum (Mbits)' (($vSwitch.DefaultFlowMinimumBandwidthAbsolute)/1000000)
  Write-Line 'Bandwidth default weight' ($vSwitch.DefaultFlowMinimumBandwidthWeight)
  Write-Line 'SR-IOV enabled' ($vSwitch.IovSupport)
  $SETenabled = ($vSwitch.EmbeddedTeamingEnabled -eq $true)
  Write-Line 'Switch-embedded Teaming enabled' $SETenabled
  if ($SETenabled) {
    $SET = (Get-VMSwitchTeam -Name $vSwitch.Name -ComputerName $ClusterNode)
    Write-Line 'SET teaming mode' ($SET.TeamingMode)
    Write-Line 'SET algorithm' ($SET.LoadBalancingAlgorithm)
    Write-Line 'SET network adapters' ($SET.NetAdapterInterfaceDescription)
  } else {
    if($vSwitch.NetAdapterInterfaceDescription -eq $null) 
    {
        Write-Line 'Network adapters connected' 'none'
    }
    else
    {
        Write-Line 'Network adapter connected' ($vSwitch.NetAdapterInterfaceDescription)
        #$cim = New-CimSession -ComputerName $clusterNode
        if ($cim -eq $null)
        {
          $vSwitchNIC = Get-NetAdapter -InterfaceDescription $vSwitch.NetAdapterInterfaceDescription
        }
        else
        {
          $vSwitchNIC = Get-NetAdapter -CimSession $cim -InterfaceDescription $vSwitch.NetAdapterInterfaceDescription
        }
        Write-Line 'Network adapter friendly name' ($vSwitchNIC.Name)
    }
  }
  $VMsConnected = (Get-VM -ComputerName $clusterNode | Get-VMNetworkAdapter | Where-Object SwitchName -EQ $vSwitch.Name | Sort-Object VMName)
  If ($VMsConnected -eq $null) {
      $VMConn = 'none'
  } Else {
      $VMConn = @()
      foreach ($VMConnected in $VMsConnected)
      {
        $VMConn += ,$VMConnected.VMName
      }
  Write-Line 'VMs connected' $VMConn
  }

  Write-Separator
  Write-Line 'vSwitch extensions' ($vSwitchExtension.Count)
  foreach ($Extension in $vSwitchExtension)
  {
  $ExtStatus = 'inactive'
  if ($Extension.Enabled)
  {
    $ExtStatus = 'active'
  }
  
  Write-Line ($Extension.Name) $ExtStatus
  }

}
}
############################################################################################################
function Get-VMGeneralInfo
{
   param
   (
     [Object]
     $vm,

     [Object]
     $clusterNode
   )

$script:ReportSectionLabel = 'V'
'Getting VM info for ' + $vm.Name + ' ...'
Write-Separator
Write-Header 3 ('VM: ' + $vm.Name)
Write-Line 'Clustered VM' ($vm.IsClustered)
if ($vm.IsClustered)
{
  $VMClusterResource = (Get-ClusterResource -VMId $vm.VMId)
  Write-Line 'Cluster group' $VMClusterResource.OwnerGroup
  Write-Line 'Cluster startup priority' $VMClusterResource.OwnerGroup.Priority
}
Write-Line 'Host' ($vm.ComputerName)
Write-Line 'State' ($vm.State)
Write-Line 'Status' ($vm.Status)
Write-Line 'VM ID' ($vm.VMId)
Write-Line 'Generation' ($vm.Generation)
Write-Line 'Version' ($vm.Version)
Write-Line 'Created on' ($vm.CreationTime)
if ($vm.Groups -ne $null) {
  Write-Line 'Member of VM Groups' $vm.Groups.Count
  foreach ($Member in $vm.Groups) {
    Write-Line $null ($vm.Groups.Name + ' (' + $vm.Groups.InstanceId + ')')
  }
}
Write-Line 'Guest FQDN' (Get-VMKVPdata -vm $vm.Name -clusterNode $clusterNode -kvpAttribute 'FullyQualifiedDomainName')
Write-Line 'Guest OS' (Get-VMKVPdata -vm $vm.Name -clusterNode $clusterNode -kvpAttribute 'OSName')
Write-Line 'Integration Services version' (Get-VMKVPdata -vm $vm.Name -clusterNode $clusterNode -kvpAttribute 'IntegrationServicesVersion')
Write-Line 'Integration Services state' ($vm.IntegrationServicesState)
Write-Line 'Automatic stop action' ($vm.AutomaticStopAction)
Write-Line 'Automatic start action' ($vm.AutomaticStartAction)
Write-Line 'Automatic start delay' ($vm.AutomaticStartDelay)
Write-Line 'Configuration path' ($vm.ConfigurationLocation)
Write-Line 'Checkpoint path' ($vm.SnapshotFileLocation)
$CheckpointType = $vm.CheckpointType
if ($CheckpointType -eq $null) {
  $CheckpointType = 'Standard (legacy)'
}
Write-Line 'Current checkpoint type' ($CheckpointType)
$VMReplica = Get-VMReplication -ComputerName $clusterNode -VMName $vm.Name -ErrorAction SilentlyContinue
If ($VMReplica -ne $null)
{
  Write-Line 'Replication mode' ($VMReplica.ReplicationMode)
  Write-Line 'Replication state' ($VMReplica.ReplicationState)
  Write-Line 'Current replica server' ($VMReplica.CurrentReplicaServerName)
  Try {
    $ReplicationFreq = ($VMReplica.ReplicationFrequencySec)
  }
  Catch {
    $ReplicationFreq = $null
  }
  If ($ReplicationFreq -ne $null) {
    Write-Line 'Replication frequency (sec)' $ReplicationFreq
  }

} else {
  Write-Line 'Replication' 'not configured'
}
$VMConnect = Get-VMConnectAccess -ComputerName $clusterNode -VMName $vm.Name
if ($VMConnect.Count -eq 0)
{
  $VMConnectUsers = 'nobody'
} else {
  $VMConnectUsers = $VMConnect.Username # -join ', '
}
Write-Line 'VMconnect.exe access granted to' $VMConnectUsers
Write-Separator
Write-Header 4 ('Checkpoints of ' + $vm.Name)
$Checkpoints = (Get-VMSnapshot -VMName $vm.Name -ComputerName $clusterNode | Sort-Object CreationTime)
if ($Checkpoints.Length -eq 0)
{
  Write-Line $null 'none'
} else {
  foreach ($Checkpoint in $Checkpoints)
  {
    Write-Line '  Name' ($Checkpoint.Name)
    Write-Line '  Path' ($Checkpoint.Path)
    Write-Line '  Created' ($Checkpoint.CreationTime)
    Write-Line '  Parent checkpoint' ($Checkpoint.ParentSnapshotName)
    Write-Separator
  }
}

if ((Get-Command Get-VMSecurity -ErrorAction SilentlyContinue) -ne $null) {
  Write-Separator
  Write-Header 4 'VM Security'
  $VMSec = (Get-VMSecurity -VM $vm)
  Write-Line 'Shielded VM' $VMSec.Shielded
  Write-Line 'TPM Enabled' $VMSec.TpmEnabled
  Write-Line 'Key Storage Drive enabled' $VMSec.KsdEnabled
  Write-Line 'State and Migration encrypted' $VMSec.EncryptStateAndVmMigrationTraffic
}
}

############################################################################################################
function Get-VMCPUInfo
{
   param
   (
     [Object]
     $vm,

     [Object]
     $clusterNode
   )

Write-Separator
Write-Header 4 'Virtual hardware'
Write-Line 'Number of CPUs' ($vm.ProcessorCount)
$vmProcessor = Get-VMProcessor -VMName $vm.Name -ComputerName $clusterNode
Write-Line 'Compatibility for older operating systems enabled' ($vmProcessor.CompatibilityForOlderOperatingSystemsEnabled)
Write-Line 'Compatibility for migration enabled' ($vmProcessor.CompatibilityForMigrationEnabled)
if ($vmProcessor.EnableHostResourceProtection -ne $null) {
  Write-Line 'Host Resource Protection enabled' ($vmProcessor.EnableHostResourceProtection)
}
if ($vmProcessor.ExposeVirtualizationExtensions -ne $null) {
  Write-Line 'Nested virtualization enabled' ($vmProcessor.ExposeVirtualizationExtensions)
}

}

############################################################################################################
function Get-VMRAMInfo
{
   param
   (
     [Object]
     $vm,

     [Object]
     $clusterNode
   )

Write-Separator
$getRAMInfo = Get-VMMemory -VMName $vm.Name -ComputerName $clusterNode
if($getRAMInfo.DynamicMemoryEnabled -eq $true)
{
    Write-Line 'RAM type' 'Dynamic Memory'
    Write-Line 'Start RAM' ([string]($getRAMInfo.Startup / 1MB) + ' MB')
    Write-Line 'Minimum RAM' ([string]($getRAMInfo.Minimum / 1MB) + ' MB')
    Write-Line 'Maximum RAM' ([string]($getRAMInfo.Maximum / 1MB) + ' MB')
}
else
{
  Write-Line 'RAM type' 'Static Memory'
  Write-Line 'RAM' ([string]($vm.MemoryStartup / 1MB) + ' MB')
}

}

############################################################################################################
function Get-VMDriveInfo
{
   param
   (
     [Object]
     $vm,

     [Object]
     $clusterNode
   )

$vmHDDs = (Get-VMHardDiskDrive -VMName $vm.Name -ComputerName $clusterNode | Sort-Object Name)

Write-Separator
Write-Line 'Number of drives' ($vmHDDs.Count)
      
ForEach($vmHDD in $vmHDDs)
{
  Write-Separator
  Write-Line 'Disk Name' ($vmHDD.Name)
  Write-Line 'Controller ID' ($vmHDD.ID)
  Write-Line 'Type' ($vmHDD.ControllerType)
  Write-Line 'Number' ($vmHDD.ControllerNumber)
  Write-Line 'Location' ($vmHDD.ControllerLocation)
  Write-Line 'Path' ($vmHDD.Path)
  $vmHDDVHD = $vmHDD.Path | Get-VHD -ComputerName $clusterNode -ErrorAction SilentlyContinue
  if ($vmHDDVHD -ne $null) {
    Write-Line 'VHD format' ($vmHDDVHD.VhdFormat)
    Write-Line 'VHD type' ($vmHDDVHD.VhdType)
    Write-Line 'Maximum capacity' ('{0:N2}' -f($vmHDDVHD.Size / 1GB) + ' GB')
    Write-Line 'Used capacity (for dynamic VHD)' ('{0:N2}' -f($vmHDDVHD.FileSize / 1GB) + ' GB')
  } else {
    Write-Line 'Disk Warning' 'Error accessing virtual disk'  
  }
}

# Get vFC, if any
$vmvSAN = (Get-VMFibreChannelHba -VMName $vm.Name -ComputerName $clusterNode | Sort-Object Name)
if ($vmvSAN -ne $null) {
  Write-Separator
  Write-Line 'Number of Fibre Channel vSANs' ($vmvSAN.Count)
      
  ForEach($vmvSAN in $vmvSAN)
  {
    Write-Separator
    Write-Line 'SAN Name' ($vmvSAN.SanName)
    Write-Line 'Primary WWNN' ($vmvSAN.WorldWideNodeNameSetA)
    Write-Line 'Primary WWPN' ($vmvSAN.WorldWidePortNameSetA)
    Write-Line 'Secondary WWNN' ($vmvSAN.WorldWideNodeNameSetB)
    Write-Line 'Secondary WWPN' ($vmvSAN.WorldWidePortNameSetB)
    Write-Line 'vSAN ID' ($vmvSAN.ID)
  }
}
}

############################################################################################################
function Get-VMNICInfo
{
   param
   (
     [Object]
     $vm,

     [Object]
     $clusterNode
   )

$vmNetCards = (Get-VMNetworkAdapter -VMName $vm.Name -ComputerName $clusterNode | Sort-Object Name,ID)
Write-Separator
Write-Line 'Number of network adapters' ($vmNetCards.Count)
ForEach($vmNetCard in $vmNetCards)
{
  Write-Separator
  Write-Line 'Virtual network adapter' ($vmNetCard.Name)
  Write-Line 'vNIC ID' ($vmNetCard.ID)
  Write-Line 'Connected' ($vmNetCard.Connected)

  #vmNetCard Switch
  if($vmNetCard.SwitchName.Length -ne 0)
  {
    Write-Line 'vSwitch connected' ($vmNetCard.SwitchName)
  }
  else
  {
    Write-Line 'vSwitch connected' 'none'
  }

  #vmNetCard MACAddress
  Write-Line 'Dynamic MAC address' ($vmNetCard.DynamicMacAddressEnabled)
  if($vmNetCard.MacAddress.Length -ne 0)
  {
    Write-Line 'MAC address' ($vmNetCard.MacAddress)
  }
  else
  {
    Write-Line 'MAC address' 'not assigned'
  }

  #vmNetCard IPAddress
  $vmnetCardIPs = $vmNetCard.IPAddresses
  if($vmNetCard.IPAddresses.Length -ne 0)
  {
    ForEach($vmnetCardIP in $vmnetCardIPs)
    {
      Write-Line 'IP address' ($vmNetCardIP)
    }
  }
  else
  {
    Write-Line 'IP address' 'not assigned'
  }
  # special features (could be extended in future versions)
  Write-Line 'DHCP Guard' ($vmNetCard.DhcpGuard)
  Write-Line 'Router Guard' ($vmNetCard.RouterGuard)
  Write-Line 'VLAN setting' ('mode ' + $vmNetCard.VlanSetting.OperationMode + ', VLAN ID ' + $vmNetCard.VlanSetting.AccessVlanId)
  if ($vmNetCard.BandwidthSetting.MinimumBandwidthAbsolute -ne $null -or $vmNetCard.BandwidthSetting.MaximumBandwidth -ne $null)
  {
    # Bandwidth settings say they use Mbit but they only multiply the GUI value by a million ...
    Write-Line 'Bandwidth setting' ('min Mbits ' + ($vmNetCard.BandwidthSetting.MinimumBandwidthAbsolute)/1000000 + ', max Mbits ' + ($vmNetCard.BandwidthSetting.MaximumBandwidth)/1000000)
  }
}
}

############################################################################################################
function Get-VMISInfo
{
   param
   (
     [Object]
     $vm,

     [Object]
     $clusterNode
   )

Write-Separator
$vmIntSer = (Get-VMIntegrationService -VMName $vm.Name -ComputerName $clusterNode | Sort-Object Name)
Write-Header 4 ('Integration services in VM ' + $vm.Name)
Write-Line 'Number of services' ($vmIntSer.Count)
foreach ($IS in $vmIntSer)
{
  if ($IS.Enabled) 
  {
    $ISActive = 'active'
  }
  else
  {
    $ISActive = 'inactive'
  }
  Write-Line ($IS.Name) $ISActive
}      
Write-Separator
}

############################################################################################################
function Get-VMKVPdata
{
   param
   (
     [Object]
     $vm,

     [Object]
     $clusterNode,

     [Object]
     $kvpAttribute
   )

$WMIFilter = "ElementName='$vm'"
$attrName = "/INSTANCE/PROPERTY[@NAME='Name']/VALUE[child::text()='$kvpAttribute']"
$VMWMI = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_ComputerSystem -Filter $WMIFilter -ComputerName $clusterNode -ErrorAction SilentlyContinue
Try {
  $VMWMI.GetRelated('Msvm_KvpExchangeComponent').GuestIntrinsicExchangeItems | % { `
        $GuestExchangeItemXml = ([XML]$_).SelectSingleNode(`
            $attrName)
       
  if ($GuestExchangeItemXml -ne $null)
  {
      $VMKVPdata = ($GuestExchangeItemXml.SelectSingleNode(`
            "/INSTANCE/PROPERTY[@NAME='Data']/VALUE/child::text()").Value)
  }   
 }
}
Catch {
  # this error handling is ugly - feel free to give me a hint ...
}
return $VMKVPData
}

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

############################################################################################################
function Check-SpecificHotFix
{
  param
  (
  [Parameter(Mandatory=$true,Position=1)]
  $HotFixId,

  [Parameter(Mandatory=$true,Position=2)]
  $ClusterNode
  )

  $IsInstalled = (Get-HotFix -Id $HotFixId -ComputerName $ClusterNode -ErrorAction SilentlyContinue)
  if ($IsInstalled -eq $null)
  {
    return $false
  } else {
    return $true
  }
}

############################################################################################################
function Show-Report()
{
if ($noview -eq $false)
{
    try {
        Invoke-Item $output
    } catch {
        'Could not launch browser. Please open file manually:'
        $output
    }
    
} 
}


############################################################################################################
function Get-ClusterFullInventory
{
  param
  (
  [Parameter(Mandatory=$false,Position=1)]
  [bool]$full
  )

# if $full is true a full cluster report will be done
# if it is false only the VMs will be reported

# try to detect a failover cluster
If (Check-Cluster) 
{
    $ClusterName = (Get-Cluster -ErrorAction SilentlyContinue).Name
}
else
{
  if ($full -eq $true)
  {
      # no cluster detected, report local host only
    'No failover cluster found or not installed on server. '
    'Report will be done in LocalHostInventory mode.'
    $script:mode = 'LocalHostInventory'
    Get-HostFullInventory ($env:COMPUTERNAME)
    Return
  }
  else
  {
      # no cluster detected, report local host only
    'No failover cluster found or not installed on server. '
    'Report will be done in VMInventoryLocalHost mode.'
    $script:mode = 'VMInventoryLocalHost'
    Get-VMInventoryHost ($env:COMPUTERNAME)
    Return
  }
}

'Creating cluster report'
New-ReportFile -RepTitle 'Hyper-V Cluster Inventory'

$cluster = Get-Cluster
$clusterNodes = (Get-ClusterNode | Sort-Object Name)

if ($full -eq $true)
{
  Get-ReportInfo -mode 'Cluster Full Inventory'
  $script:ReportSectionLabel = 'C'

  Get-ClusterInfo 

  foreach ($Node in $clusterNodes)
  {
      # connect only if host reacts to ping
      'Contacting '+ $Node.Name + ' ...'
      if (Test-Connection -ComputerName $Node -Quiet)
      {
        #Host
        $script:ReportSectionLabel = 'H'
        $HostCIMSession = New-CimSession -ComputerName $Node -ErrorAction SilentlyContinue
        Get-HostOSInfo -clusterNode $Node
        Get-HostGeneralInfo -clusterNode $Node
        Get-HostHWInfo -clusterNode $Node
        Get-HostCPUInfo -clusterNode $Node
        if ($HostCIMSession -ne $null)
        {
          Get-HostStorageInfo -clusterNode $Node -cim $HostCIMSession
          Get-HostNICInfo -clusterNode $Node -cim $HostCIMSession
          Get-HostvSwitchInfo -clusterNode $Node -cim $HostCIMSession
        }
        else
        {
          'Could not create CIM session for host ' + $Node
          'Skipping host drives, host NICs and host vSwitches.'
          Write-Header 3 'Host drives, networks and vSwitches skipped: No CIM connection'
        }
        #VMs
        $vms = (Get-VM -ComputerName $Node | Sort-Object Name)
        Get-HostVMInfo -clusterNode $Node -vms $vms
      } else {
        '# Host ' + $Node.Name + ' does not reply. Skipping host. #'
        Write-Header 3 ('Host ' + $Node.Name + ' does not reply. Skipping host.')
      }
  }
  Write-Separator
  $script:ReportSectionLabel = 'C'
  Write-Header 1 ("Cluster-wide resource assignments for $ClusterName")
  Write-Line 'Sum of vCPUs' $script:GlobalvCPU
  Write-Line 'Sum of VM RAM (static/startup) in GB' ($script:GlobalVMRAM/1GB)
  Write-Line 'Sum of VM RAM (maximum Dynamic) in GB' ($script:GlobalVMRAMMax/1GB)
  Write-Separator
}
else
{
  Get-ReportInfo -mode 'VM Inventory, Cluster and Hosts'
}

Write-Header 1 'Virtual Machine information'
Write-Header 2 ('VMs in cluster ' + $ClusterName)
'Getting VMs per cluster ...'
$script:ReportSectionLabel = 'V'
#$vms = (Get-ClusterGroup -Cluster $cluster | Where-Object {$_.GroupType -eq 'VirtualMachine'} | Sort-Object Name)
#$vms = (Get-VM -ComputerName $cluster | Where-Object {$_.IsClustered -eq $true} | Sort-Object Name)
$vms = (Get-ClusterGroup -Cluster $cluster | Where-Object {$_.GroupType -eq 'VirtualMachine'} | Sort-Object Name | Get-VM)
Write-Line 'Number of VMs in cluster' $vms.count
Write-Separator
foreach ($vm in $vms)
{
    $vmrole = (Get-ClusterResource -VMId $vm.VMId)
    #(Get-VM -Name $vmrole -ComputerName $vmrole.OwnerNode)
    Get-VMGeneralInfo -vm $vm -clusterNode $vmrole.OwnerNode
    Get-VMCPUInfo -vm $vm -clusterNode $vmrole.OwnerNode
    Get-VMRAMInfo -vm $vm -clusterNode $vmrole.OwnerNode
    Get-VMDriveInfo -vm $vm -clusterNode $vmrole.OwnerNode
    Get-VMNICInfo -vm $vm -clusterNode $vmrole.OwnerNode
    Get-VMISInfo -vm $vm -clusterNode $vmrole.OwnerNode
}

'Getting VMs per host ...'
foreach ($Node in $clusterNodes)
{
  Write-Header 2 ('Non-clustered VMs on host ' + $Node.Name)
  # connect only if host reacts to ping
  'Contacting '+ $Node.Name + ' ...'
  if (Test-Connection -ComputerName $Node -Quiet)
  {
    #VMs
    $vms = (Get-VM -ComputerName $Node |  Where-Object {$_.IsClustered -ne $true} | Sort-Object Name)
    Write-Line 'Number of VMs on host' $vms.count
    foreach ($vm in $vms)
    {
        vmGeneralInfo -vm $vm -clusterNode $Node
        vmCPUInfo -vm $vm -clusterNode $Node
        vmRAMInfo -vm $vm -clusterNode $Node
        vmDriveInfo -vm $vm -clusterNode $Node
        vmNICInfo -vm $vm -clusterNode $Node
        vmISInfo -vm $vm -clusterNode $Node
  }
  } else {
      '# Host ' + $Node.Name + ' does not reply. Skipping host. #'
      Write-Header 3 ('Host ' + $Node.Name + ' does not reply. Skipping host.')
  }
  Write-Separator
}

Show-Report
}

############################################################################################################
function Get-HostOnlyInventory
{
  param
  (
  [Parameter(Mandatory=$false,Position=1)]
  [string]$Node
  )

if ($Node.Length -eq 0) {
    '##################'
    'No host specified.'
    'Aborting script.'
    Return
}

# connect only if host reacts to ping
'Contacting '+ $Node + ' ...'
if (Test-Connection -ComputerName $Node -Quiet)
{
  "Creating host-only report for $Node"
  New-ReportFile -RepTitle 'Hyper-V Host Inventory'
  Get-ReportInfo -mode 'Host Full Inventory'
  $script:ReportSectionLabel = 'H'

  #Host
  $script:ReportSectionLabel = 'H'
  $HostCIMSession = New-CimSession -ComputerName $Node -ErrorAction SilentlyContinue
  Get-HostOSInfo -clusterNode $Node
  Get-HostGeneralInfo -clusterNode $Node
  Get-HostHWInfo -clusterNode $Node
  Get-HostCPUInfo -clusterNode $Node
  if ($HostCIMSession -ne $null)
  {
    Get-HostStorageInfo -clusterNode $Node -cim $HostCIMSession
    Get-HostNICInfo -clusterNode $Node -cim $HostCIMSession
    Get-HostvSwitchInfo -clusterNode $Node -cim $HostCIMSession
  }
  else
  {
    'Could not create CIM session for host ' + $Node
    'Skipping host drives, host NICs and host vSwitches.'
    Write-Header 3 'Host drives, networks and vSwitches skipped: No CIM connection'
  }
  #VMs
  $vms = (Get-VM -ComputerName $Node | Sort-Object Name)
  Get-HostVMInfo -clusterNode $Node -vms $vms
  Show-Report

  } else {
  '#' * (21 + ($Node).Length)
  "Host $Node does not reply."
  'Aborting script.'
  Return
  }

}

function Get-VMInventoryHost()
{
  param
  (
  [Parameter(Mandatory=$false,Position=1)]
  [string]$Node
  )

# creates an inventory reports of all VMs on a single host

if ($Node.Length -eq 0) {
    '##################'
    'No host specified.'
    'Aborting script.'
    Return
}

# connect only if host reacts to ping
'Contacting '+ $Node + ' ...'
if (Test-Connection -ComputerName $Node -Quiet)
{

  "Creating VM inventory for host $Node"
  New-ReportFile -RepTitle 'Hyper-V VM Inventory'

  Get-ReportInfo -mode 'VM Inventory, Single Host'
  $script:ReportSectionLabel = 'V'

  Write-Header 1 "VMs on host $Node"
  #VMs
  $vms = (Get-VM -ComputerName $Node | Sort-Object Name)
  Write-Line 'Number of VMs on host' $vms.count
  foreach ($vm in $vms)
  {
      vmGeneralInfo -vm $vm -clusterNode $Node
      vmCPUInfo -vm $vm -clusterNode $Node
      vmRAMInfo -vm $vm -clusterNode $Node
      vmDriveInfo -vm $vm -clusterNode $Node
      vmNICInfo -vm $vm -clusterNode $Node
      vmISInfo -vm $vm -clusterNode $Node
  }

  Show-Report

  } else {
  '#' * (21 + ($Node).Length)
  "Host $Node does not reply."
  'Aborting script.'
  Return
  }
}

function Get-SingleVMInventory()
{
  param
  (
  [Parameter(Mandatory=$false,Position=1)]
  [string]$Node,

  [Parameter(Mandatory=$false,Position=2)]
  [string]$VMName
  )

# creates an inventory report of a single VM on a specified host

if ($Node.Length -eq 0) {
    '##################'
    'No host specified.'
    'Aborting script.'
    Return
}

if ($VMName.Length -eq 0) {
    '################'
    'No VM specified.'
    'Aborting script.'
    Return
}

# connect only if host reacts to ping
'Contacting '+ $Node + ' ...'
if (-not (Test-Connection -ComputerName $Node -Quiet)) {
  '#' * (21 + ($Node).Length)
  "Host $Node does not reply."
  'Aborting script.'
  Return
}

$vm = (Get-VM -ComputerName $Node -Name $VMName -ErrorAction SilentlyContinue)
if ($vm -eq $null) {
     '#' * (14 + ($VMName).Length)
    "VM $VMName not found."
    'Aborting script.'
    Return
}

"Creating single VM report for $VMName"
New-ReportFile 'Hyper-V Single VM Inventory'

Get-ReportInfo -mode 'Single VM Inventory'
$script:ReportSectionLabel = 'V'

Write-Header 1 "VM $VMName on host $Node"

vmGeneralInfo -vm $vm -clusterNode $Node
vmCPUInfo -vm $vm -clusterNode $Node
vmRAMInfo -vm $vm -clusterNode $Node
vmDriveInfo -vm $vm -clusterNode $Node
vmNICInfo -vm $vm -clusterNode $Node
vmISInfo -vm $vm -clusterNode $Node


Show-Report
}

function Get-ClusterOnlyInventory
{

If (!(Check-Cluster))
{
  # no cluster detected, cancel
  'No failover cluster found or not installed on server. '
  'Cancelling report.'
  Return
}

'Creating cluster-only report'
$script:ReportSectionLabel = 'C'
New-ReportFile -RepTitle 'Hyper-V Cluster-Only Inventory'

Get-ReportInfo -mode 'Cluster-Only Inventory'
Get-ClusterInfo
Show-Report

}

function Get-HostFullInventory
{
  param
  (
  [Parameter(Mandatory=$false,Position=1)]
  [string]$Node
  )

if ($Node.Length -eq 0) {
    '##################'
    'No host specified.'
    'Aborting script.'
    Return
}

# connect only if host reacts to ping
'Contacting '+ $Node + ' ...'
if (Test-Connection -ComputerName $Node -Quiet)
{
  "Creating host report for $Node"
  New-ReportFile 'Hyper-V Host Inventory'

  Get-ReportInfo -mode 'Host Full Inventory'
  $script:ReportSectionLabel = 'H'

  #Host
  $HostCIMSession = New-CimSession -ComputerName $Node -ErrorAction SilentlyContinue
  Get-HostOSInfo -clusterNode $Node
  Get-HostGeneralInfo -clusterNode $Node
  Get-HostHWInfo -clusterNode $Node
  Get-HostCPUInfo -clusterNode $Node
  if ($HostCIMSession -ne $null)
  {
    Get-HostStorageInfo -clusterNode $Node -cim $HostCIMSession
    Get-HostNICInfo -clusterNode $Node -cim $HostCIMSession
    Get-HostvSwitchInfo -clusterNode $Node -cim $HostCIMSession
  }
  else
  {
    'Could not create CIM session for host ' + $Node
    'Skipping host drives, host NICs and host vSwitches.'
    Write-Header 3 'Host drives, networks and vSwitches skipped: No CIM connection'
  }
  #VMs
  $vms = (Get-VM -ComputerName $Node | Sort-Object Name)
  Get-HostVMInfo -clusterNode $Node -vms $vms
  foreach ($vm in $vms)
  {
      vmGeneralInfo -vm $vm -clusterNode $Node
      vmCPUInfo -vm $vm -clusterNode $Node
      vmRAMInfo -vm $vm -clusterNode $Node
      vmDriveInfo -vm $vm -clusterNode $Node
      vmNICInfo -vm $vm -clusterNode $Node
      vmISInfo -vm $vm -clusterNode $Node

  }
  Show-Report

  } else {
  '#' * (21 + ($Node).Length)
  "Host $Node does not reply."
  'Aborting script.'
  Return
  }
}


function Select-ReportMode()
{
# determine output format
# HTML is default unless TXT is specified
switch($format)
{
  'txt' { 
            $format = 'TXT'
            $RepExt = '.txt'
        }
  'text' { 
            $format = 'TXT'
            $RepExt = '.txt'
        }
  default {
            $format = 'HTML'
            $RepExt = '.html'
          }
}

if ($output.Length -eq 0)
{
    $myDate = Get-Date -Format 'yyyyMMdd-HHmmss'
    $output = "$env:userprofile\Documents\Hyper-V-Inventory-$myDate$RepExt"
}

if ($mode.Length -ne 0)
{
    switch($mode)
    {
    'ClusterFullInventory' {Get-ClusterFullInventory -full $true }
    'LocalHostInventory' {Get-HostFullInventory ($env:COMPUTERNAME)}
    'RemoteHostInventory' {Get-HostFullInventory (($remoteHost).ToUpper())}
    'ClusterOnlyInventory' {Get-ClusterOnlyInventory}
    'LocalHostOnlyInventory' {Get-HostOnlyInventory ($env:COMPUTERNAME)}
    'RemoteHostOnlyInventory' {Get-HostOnlyInventory (($remoteHost).ToUpper())}
    'VMInventoryCluster' {Get-ClusterFullInventory -full $false }
    'VMInventoryLocalHost' {Get-VMInventoryHost ($env:COMPUTERNAME)}
    'VMInventoryRemoteHost' {Get-VMInventoryHost (($remoteHost).ToUpper())}
    'SingleVMInventory' {Get-SingleVMInventory (($remoteHost).ToUpper()) (($VMName).ToUpper())}
    default { 'Invalid mode.' 
              Return
            }
    }
    Close-ReportFile
    Return
}


"Welcome to Get-HyperVInventory (version $ScriptVersion).",
'',
'Need instructions?  -> Please read the README or see online help',
'Enter one of the numbers to select the mode.',
'' | Write-Host

'#####################################################################',
'# No.      Mode                                 Description         #',
'# ----------------------------------------------------------------- #',
'#  1       Cluster Full Inventory               Cluster, Hosts, VMs #',
'#  2       Local Host Full Inventory            Host, VMs           #',
'#  3       Remote Host Full Inventory           Host, VMs           #',
'#  4       Cluster-Only Inventory               Cluster             #',
'#  5       Local Host-Only Inventory            Host                #',
'#  6       Remote Host-Only Inventory           Host                #',
'#  7       VM Inventory, Cluster and Hosts      VMs                 #',
'#  8       VM Inventory, Local Host             VMs                 #',
'#  9       VM Inventory, Remote Host            VMs                 #',
'#  10      Single VM Inventory                  VM                  #',
'#                                                                   #',
'#  0       just exit, do nothing                                    #',
'#####################################################################',
'',
'All reports can be launched from the menu, you will be prompted for missing values if necessary.',
'If you prefer automatic reports of the environment in separate files use the script',
'Get-HyperVInventory-MultipleReports.ps1 in the same folder.',
'If you need to specify the report format or file path, run this script via command line.',
'' | Write-Host
$choice = Read-Host 'Select mode'

switch($choice)
{
  0 { return }
  1 {Get-ClusterFullInventory -full $true}
  2 {Get-HostFullInventory ($env:COMPUTERNAME)}
  3 {Get-HostFullInventory ((Read-Host 'Enter remote host name').ToUpper())}
  4 {Get-ClusterOnlyInventory}
  5 {Get-HostOnlyInventory ($env:COMPUTERNAME)}
  6 {Get-HostOnlyInventory ((Read-Host 'Enter remote host name').ToUpper())}
  7 {Get-ClusterFullInventory -full $false}
  8 {Get-VMInventoryHost ($env:COMPUTERNAME)}
  9 {Get-VMInventoryHost ((Read-Host 'Enter remote host name').ToUpper())}
  10 {Get-SingleVMInventory -Node ((Read-Host 'Enter host name').ToUpper())  ((Read-Host 'Enter VM name').ToUpper())}
  default {'Please enter a valid number from 0 to 10.'
           Return
          }
}
Close-ReportFile
}

function New-ReportFile 
{
   param
   (
  [Parameter(Mandatory=$false,Position=1)]
  [string] $RepTitle
   )

"`nReport file format: $format"
New-Item $output -ItemType file -Force | Out-Null
"Report file will be stored at $output"

if ($RepTitle -eq $null)
{
  $RepTitle = 'Hyper-V Environment Report'
}
if ($format -eq 'HTML')
{
  $myTime = (Get-Date).DateTime
  $HTMLHead = "<html>
  <head>
  <title>$RepTitle ($myTime)</title>
  <style type=`"text/css`">
  body { margin-top:0px; margin-bottom:20px; margin-left:20px; margin-right:20px; background-color:white;  }
  p,ul,ol,dt,div,td,th,address,blockquote,nobr,b,i,input,textarea,button,select
       { font-family:Calibri,Verdana,Arial,sans-serif;
         margin-top:0;
         margin-bottom:10;
  }
  p.link
	  { margin-left: 20px;
	  }
  h1,h2,h3,h4 
	  { font-family:Calibri,Verdana,Arial,sans-serif; 
	  }
  a 
	  { font-family:Calibri,Verdana,Arial,sans-serif; 
	  }
  tr.r0
    { background-color: #EEEEEE;
     }
  tr.r1
    { background-color: #DDDDDD; }
  td.M
    { background-color: #999999; 
      font-size: small;
      font-style: italic;
    }
  td.C
    { background-color: #AAAAAA; 
      font-size: small;
      font-style: italic;
    }
  td.H
    { background-color: #BBBBBB;  
      font-size: small;
      font-style: italic;
    }
  td.V
    { background-color: #CCCCCC;  
      font-size: small;
      font-style: italic;
    }

  </style>
  </head><body>
  <table>"
  $HTMLHead | Out-File $output -Append
}
}

function Close-ReportFile
{
if ($format -eq 'HTML')
{
  "</table>
  <h3 style=`"margin-top:50px;`">Symbols</h3>
  <table>
  <tr><td class=`"M`">&nbsp;M</td><td>Report metadata</td></tr>
  <tr><td class=`"C`">&nbsp;C</td><td>Cluster-related data</td></tr>
  <tr><td class=`"H`">&nbsp;H</td><td>Host-related data</td></tr>
  <tr><td class=`"V`">&nbsp;V</td><td>VM-related data</td></tr>
  </table>
  <p style=`"margin-top:50px;font-size:small;`">Report created with <a href=`"https://gallery.technet.microsoft.com/Get-HyperVInventory-Create-2c368c50`">Get-HyperVInventory</a> $ScriptVersion by <a href=`"http://www.michael-wessel.de`">michael-wessel.de</a>.</p>
  </body></html>"  | Out-File $output -Append
}

}

function Test-Admin
{
  $result = (whoami.exe /groups) -like '*S-1-16-8192*'
  $result.Count -eq 0
}

function Write-Line
{
  param
  (
  [Parameter(Mandatory=$false,Position=1)]
  [string]$Label,

  [Parameter(Mandatory=$false,Position=2)]
  $Value
  )
  switch($format)
  {
    'TXT' {
      if ($Value -is [system.array])
      {
        $Value = "`n  " + $Value -join "`n" + "`n  "
      }
      if ($Label)
      {
        $Label = $Label + ': '
      }
      else
      {
        $Label = '  '
      }
      $Label + $Value | Out-File $output -Append
    }
    'HTML' {
      if ($Value -is [system.array])
      {
        $Value = '<ul><li>' + ($Value -join '</li><li>') + '</li></ul>'
      }
      if (!$Label)
      {
        $Label = '&nbsp;'
      }
      '<tr class="r' + $RowChange + '"><td class="' + $ReportSectionLabel + '">&nbsp;' + $ReportSectionLabel + '&nbsp;</td><td><em>' + $Label + '</em></td><td>' + $value + '</td></tr>' | Out-File $output -Append
    }
  }
  
  # change row colour selector
  if ($RowChange -eq 0)
  { $script:RowChange = 1 }
  else
  { $script:RowChange = 0 }
  
}


function Write-LineIndent
{
  param
  (
  [Parameter(Mandatory=$false,Position=1)]
  [string]$Label,

  [Parameter(Mandatory=$false,Position=2)]
  $Value,

  [Parameter(Mandatory=$false,Position=3)]
  $Level
  )

  switch($format)
  {
    'TXT' {
      if ($Value -is [system.array])
      {
        $Value = "`n  " + $Value -join "`n" + "`n  "
      }
      if ($Label)
      {
        $Label = $Label + ': '
      }
      else
      {
        $Label = '  '
      }
      $Label + ('   ' * $Level) + $Value | Out-File $output -Append
    }
    'HTML' {
      if ($Value -is [system.array])
      {
        $Value = '<ul><li>' + ($Value -join '</li><li>') + '</li></ul>'
      }
      if (!$Label)
      {
        $Label = '&nbsp;'
      }
      '<tr class="r' + $script:RowChange + '"><td class="' + $script:ReportSectionLabel + '">&nbsp;' + $script:ReportSectionLabel + '&nbsp;</td><td><em>' + $Label + '</em></td><td><span style="margin-left:' + ($Level * 10) + 'px;">' + $value + '</span></td></tr>' | Out-File $output -Append
    }
  }
  
  # change row colour selector
  if ($script:RowChange -eq 0)
  { $script:RowChange = 1 }
  else
  { $script:RowChange = 0 }
  
}

function Write-Header
{
  param
  (
  [int]$Level,
  [string]$Value
  )
  switch($format)
  {
    'TXT' {
      if ($Level -eq $null) {$Level = 4}
      $HeaderPrefix = '#' * (4 - $Level)
      $HeaderSuffix = '#' * (4 - $Level)
      $HeaderPrefix + ' ' + $Value + ' ' + $HeaderSuffix | Out-File $output -Append
    }
    'HTML' {
      if ($Level -eq $null) {$Level = 4}
      $HeaderPrefix = "<h$Level>"
      $HeaderSuffix = "</h$Level>"
      '<tr><td colspan="3">' + $HeaderPrefix + ' ' + $Value + ' ' + $HeaderSuffix + '</td></tr>' | Out-File $output -Append
    }
  }
}

function Write-Separator
{
  param
  (
  )
switch($format)
{
  'TXT' {
    '' | Out-File $output -Append
  }
  'HTML' {
    '<tr><td colspan="3">&nbsp;</td></tr>' | Out-File $output -Append
  }
}

}


############################################################################################################
#PROGRAM START

Get-Date
"Launching and checking ...`n"

# version number
$ScriptVersion = 'v2.4'

# get local computer name
$LocalHostName = $env:COMPUTERNAME

# set global variable for table background changing
[int]$RowChange = 0

# set global variable for table section label
# M is for Meta
# C is for Cluster
# H is for Host
# V is for VM
$ReportSectionLabel = 'M'

# set global variables for vCPU and VM-RAM count
$GlobalvCPU = 0
$GlobalVMRAM = 0
$GlobalVMRAMMax = 0

# check OS version as we can only run on Winodws 2012/Windows 8 or later
If ([int](Get-CimInstance Win32_OperatingSystem).BuildNumber -lt 9200)
{ 
    '#' * (76 + ($LocalHostName).Length)
    "Sorry, the script cannot execute on $LocalHostName. It needs at least Windows Server 2012."
    Return
}

# check for server
$IsClient = (((Get-CimInstance Win32_OperatingSystem).Caption).contains('Server') -eq $false)


# check if we're running in an elevated shell
if ((Test-Admin) -eq $false)
{
    '#' * 74
    'Sorry, the script can only run as a local administrator.'
    'Make sure to launch the PowerShell session explicitly as an Administrator.'
    Return
}

# check if Hyper-V role is present
# the follwoing method is slower than Get-WindowsFeature but it runs on clients as well
$isHyperVInstalled = (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).State -eq 'Enabled'
if ($IsHyperVInstalled -ne $true) 
    {
    # no Hyper-V detected, exit script
    '#' * (25 + ($LocalHostName).Length)
    "Hyper-V not detected on $LocalHostName."
    'Please run this script locally on a Hyper-V host.'
    Return
    }

Select-ReportMode
'Finished'
Get-Date
