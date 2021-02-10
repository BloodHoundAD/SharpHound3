function Invoke-BloodHound{
    <#
    .SYNOPSIS

        Runs the BloodHound C# Ingestor using reflection. The assembly is stored in this file.

    .DESCRIPTION

        Using reflection and assembly.load, load the compiled BloodHound C# ingestor into memory
        and run it without touching disk. Parameters are converted to the equivalent CLI arguments
        for the SharpHound executable and passed in via reflection. The appropriate function
        calls are made in order to ensure that assembly dependencies are loaded properly.

    .PARAMETER CollectionMethod

        Specifies the CollectionMethod being used. Possible value are:
            Group - Collect group membership information
            LocalGroup - Collect local group information for computers
            LocalAdmin - Collect local admin users for computers
            RDP - Collect remote desktop users for computers
            DCOM - Collect distributed COM users for computers
            PSRemote - Collected members of the Remote Management Users group for computers
            Session - Collect session information for computers
            SessionLoop - Continuously collect session information until killed
            Trusts - Enumerate domain trust data
            ACL - Collect ACL (Access Control List) data
            Container - Collect GPO/OU Data
            ComputerOnly - Collects Local Admin and Session data
            GPOLocalGroup - Collects Local Admin information using GPO (Group Policy Objects)
            LoggedOn - Collects session information using privileged methods (needs admin!)
            ObjectProps - Collects node property information for users and computers
            SPNTargets - Collects SPN targets (currently only MSSQL)
            Default - Collects Group Membership, Local Admin, Sessions, and Domain Trusts
            DcOnly - Collects Group Membership, ACLs, ObjectProps, Trusts, Containers, and GPO Admins
            All - Collect all data except GPOLocalGroup

        This can be a list of comma seperated valued as well to run multiple collection methods!

    .PARAMETER Stealth

        Use stealth collection options, will sacrifice data quality in favor of much reduced
        network impact

    .PARAMETER Domain

        Specifies the domain to enumerate. If not specified, will enumerate the current
        domain your user context specifies.

    .PARAMETER WindowsOnly

        Limits computer collection to systems that have an operatingssytem attribute that matches *Windows*

    .PARAMETER ComputerFile

        A file containing a list of computers to enumerate. This option can only be used with the following Collection Methods:
        Session, SessionLoop, LocalGroup, ComputerOnly, LoggedOn

    .PARAMETER OutputDirectory

        Folder to output files too

    .PARAMETER OutputPrefix

        Prefix to add to output files

    .PARAMETER PrettyJSON

        Output "pretty" json with formatting for readability

    .PARAMETER CacheFilename

        Name for the cache file dropped to disk (default: unique hash generated per machine)

    .PARAMETER RandomizeFilenames

        Randomize file names completely

    .PARAMETER ZipFilename

        Name for the zip file output by data collection

    .PARAMETER NoSaveCache

        Don't write the cache file to disk. Caching will still be performed in memory.

    .PARAMETER EncryptZip

        Encrypt the zip file with a random password

    .PARAMETER NoZip

        Do NOT zip the json files

    .PARAMETER InvalidateCache

        Invalidate and rebuild the cache file

    .PARAMETER SearchBase

        DistinguishedName to start LDAP searches at. Equivalent to the old -Ou option

    .PARAMETER LdapFilter

        Append this ldap filter to the search filter to further filter the results enumerated

    .PARAMETER DomainController

        Domain Controller to connect too. Specifiying this can result in data loss

    .PARAMETER LdapPort

        Port LDAP is running on. Defaults to 389/686 for LDAPS

    .PARAMETER SecureLDAP

        Connect to LDAPS (LDAP SSL) instead of regular LDAP

    .PARAMETER DisableKerberosSigning

        Disables keberos signing/sealing, making LDAP traffic viewable

    .PARAMETER LdapUsername

        Username for connecting to LDAP. Use this if you're using a non-domain account for connecting to computers

    .PARAMETER LdapPassword

        Password for connecting to LDAP. Use this if you're using a non-domain account for connecting to computers

    .PARAMETER SkipPortScan

        Skip SMB port checks when connecting to computers

    .PARAMETER PortScanTimeout

        Timeout for SMB port checks

    .PARAMETER ExcludeDomainControllers

        Exclude domain controllers from enumeration (usefult o avoid Microsoft ATP/ATA)

    .PARAMETER Throttle

        Throttle requests to computers (in milliseconds)

    .PARAMETER Jitter

        Add jitter to throttle

    .PARAMETER OverrideUserName

        Override username to filter for NetSessionEnum

    .PARAMETER NoRegistryLoggedOn

        Disable remote registry check in LoggedOn collection

    .PARAMETER DumpComputerStatus

        Dumps error codes from attempts to connect to computers

    .PARAMETER RealDNSName

        Overrides the DNS name used for API calls

    .PARAMETER CollectAllProperties

        Collect all string LDAP properties on objects

    .PARAMETER StatusInterval

        Interval for displaying status in milliseconds

    .PARAMETER Loop

        Perform looping for computer collection

    .PARAMETER LoopDuration

        Duration to perform looping (Default 02:00:00)

    .PARAMETER LoopInterval

        Interval to sleep between loops (Default 00:05:00)

    .PARAMETER V

        Enable Verbose Output

    .PARAMETER Help

        Display this help screen

    .PARAMETER Version

        Display version information

    .EXAMPLE

        PS C:\> Invoke-BloodHound

        Executes the default collection options and exports JSONs to the current directory, compresses the data to a zip file,
        and then removes the JSON files from disk

    .EXAMPLE

        PS C:\> Invoke-BloodHound -Loop -LoopInterval 00:01:00 -LoopDuration 00:10:00

        Executes session collection in a loop. Will wait 1 minute after each run to continue collection
        and will continue running for 10 minutes after which the script will exit

    .EXAMPLE

        PS C:\> Invoke-BloodHound -CollectionMethod All

        Runs ACL, ObjectProps, Container, and Default collection methods, compresses the data to a zip file,
        and then removes the JSON files from disk

    .EXAMPLE

        PS C:\> Invoke-BloodHound -CollectionMethod DCOnly -NoSaveCache -RandomizeFilenames -EncryptZip

        (Opsec!) Run LDAP only collection methods (Groups, Trusts, ObjectProps, ACL, Containers, GPO Admins) without outputting the cache file to disk.
        Randomizes filenames of the JSON files and the zip file and adds a password to the zip file
    #>

    [CmdletBinding(PositionalBinding=$false)]
    param(
        [Alias("c")]
        [String[]]
        $CollectionMethod = [String[]] @('Default'),

        [Switch]
        $Stealth,

        [Alias("d")]
        [String]
        $Domain,

        [Switch]
        $WindowsOnly,

        [String]
        $ComputerFile,

        [ValidateScript({ Test-Path -Path $_ })]
        [String]
        $OutputDirectory = $(Get-Location),

        [ValidateNotNullOrEmpty()]
        [String]
        $OutputPrefix,

        [Switch]
        $PrettyJson,

        [String]
        $CacheFileName,

        [Switch]
        $RandomizeFilenames,

        [String]
        $ZipFilename,

        [Switch]
        $NoSaveCache,

        [Switch]
        $EncryptZip,

        [Switch]
        $InvalidateCache,

        [String]
        $SearchBase,

        [String]
        $LdapFilter,

        [string]
        $DomainController,

        [ValidateRange(0,65535)]
        [Int]
        $LdapPort,

        [Switch]
        $SecureLdap,

        [Switch]
        $DisableKerberosSigning,

        [String]
        $LdapUsername,

        [String]
        $LdapPassword,

        [Switch]
        $SkipPortScan,

        [ValidateRange(50,5000)]
        [Int]
        $PortScanTimeout = 2000,

        [Switch]
        $ExcludeDomainControllers,

        [ValidateRange(0,100)]
        [Int]
        $Jitter,

        [Int]
        $Throttle,

        [String]
        $OverrideUsername,

        [Switch]
        $NoRegistryLoggedOn,

        [Switch]
        $DumpComputerStatus,

        [String]
        $RealDNSName,

        [Switch]
        $CollectAllProperties,

        [ValidateRange(500,60000)]
        [Int]
        $StatusInterval,

        [Switch]
        $Loop,

        [String]
        $LoopDuration,

        [String]
        $LoopInterval,

        [Switch]
        $V,

        [Alias("h")]
        [Switch]
        $Help,

        [Switch]
        $Version
    )

    $vars = New-Object System.Collections.Generic.List[System.Object]

    if ($CollectionMethod){
        $vars.Add("--CollectionMethod");
        foreach ($cmethod in $CollectionMethod){
            $vars.Add($cmethod);
        }
    }

    if ($Domain){
        $vars.Add("--Domain");
        $vars.Add($Domain);
    }

    if ($Stealth){
        $vars.Add("--Stealth")
    }

    if ($WindowsOnly){
        $vars.Add("--WindowsOnly")
    }

    if ($ComputerFile){
        $vars.Add("--ComputerFile");
        $vars.Add($ComputerFile);
    }

    if ($OutputDirectory){
        $vars.Add("--OutputDirectory");
        $vars.Add($OutputDirectory);
    }

    if ($OutputPrefix){
        $vars.Add("--OutputPrefix");
        $vars.Add($OutputPrefix);
    }

    if ($PrettyJson){
        $vars.Add("--PrettyJson");
    }

    if ($CacheFileName){
        $vars.Add("--CacheFileName");
        $vars.Add($CacheFileName);
    }

     if ($RandomizeFilenames){
        $vars.Add("--RandomizeFilenames");
    }

    if ($ZipFileName){
        $vars.Add("--ZipFileName");
        $vars.Add($ZipFileName);
    }

    if ($NoSaveCache){
        $vars.Add("--NoSaveCache");
    }

    if ($EncryptZip){
        $vars.Add("--EncryptZip");
    }

    if ($NoZip){
        $vars.Add("--NoZip");
    }

    if ($InvalidateCache){
        $vars.Add("--InvalidateCache");
    }

    if ($LdapFilter){
        $vars.Add("--LdapFilter");
        $vars.Add($LdapFilter);
    }

    if ($DomainController){
        $vars.Add("--DomainController");
        $vars.Add($DomainController);
    }

    if ($LdapPort){
        $vars.Add("--LdapPort");
        $vars.Add($LdapPort);
    }

    if ($SecureLdap){
        $vars.Add("--SecureLdap");
    }

    if ($DisableKerberosSigning){
        $vars.Add("--DisableKerberosSigning");
    }

    if ($LdapUsername){
        $vars.Add("--LdapUsername");
        $vars.Add($LdapUsername);
    }

    if ($LdapPassword){
        $vars.Add("--LdapPassword");
        $vars.Add($LdapPassword);
    }

    if ($SearchBase){
        $vars.Add("--SearchBase")
        $vars.Add($SearchBase)
    }

    if ($SkipPortScan){
        $vars.Add("--SkipPortScan");
    }

    if ($PortScanTimeout){
        $vars.Add("--PortScanTimeout")
        $vars.Add($PortScanTimeout)
    }

    if ($ExcludeDomainControllers){
        $vars.Add("--ExcludeDomainControllers")
    }

    if ($Throttle){
        $vars.Add("--Throttle");
        $vars.Add($Throttle);
    }

    if ($Jitter -gt 0){
        $vars.Add("--Jitter");
        $vars.Add($Jitter);
    }

    if ($OverrideUserName){
        $vars.Add("--OverrideUserName")
        $vars.Add($OverrideUsername)
    }

    if ($NoRegistryLoggedOn){
        $vars.Add("--NoRegistryLoggedOn")
    }

    if ($DumpComputerStatus){
        $vars.Add("--DumpComputerStatus")
    }

    if ($RealDNSName){
        $vars.Add("--RealDNSName")
        $vars.Add($RealDNSName)
    }

    if ($CollectAllProperties){
        $vars.Add("--CollectAllProperties")
    }

    if ($StatusInterval){
        $vars.Add("--StatusInterval")
        $vars.Add($StatusInterval)
    }

    if ($V){
        $vars.Add("-v");
    }

    if ($Loop){
        $vars.Add("--Loop")
    }

    if ($LoopDuration){
        $vars.Add("--LoopDuration")
        $vars.Add($LoopDuration)
    }

    if ($LoopInterval){
        $vars.Add("--LoopInterval")
        $vars.Add($LoopInterval)
    }

    if ($Help){
        $vars.Add("--Help");
    }

    if ($Version){
        $vars.clear();
        $vars.Add("--Version");
    }

    $passed = [string[]]$vars.ToArray()


    #ENCODEDCONTENTHERE
}
