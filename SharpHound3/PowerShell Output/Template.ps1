function Invoke-SharpHound{
	<#
	.SYNOPSIS
		
		Runs the SharpHound C# Ingestor using reflection. The assembly is stored in base64 format in this file

	.DESCRIPTION
		
		Using reflection and assembly.load, load the compiled SharpHound C# ingestor into memory
        and run it without touching disk. Parameters are converted to the equivalent CLI arguments
        for the SharpHound executable and passed in via reflection. The appropriate function
        calls are made in order to ensure that assembly dependencies are loaded properly.

	.PARAMETER CollectionMethod

		Specifies the CollectionMethods being used, comma seperated
			

	#>
}



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
            Session - Collect session information for computers
            SessionLoop - Continuously collect session information until killed
            Trusts - Enumerate domain trust data
            ACL - Collect ACL (Access Control List) data
            Container - Collect GPO/OU Data
            ComputerOnly - Collects Local Admin and Session data
            GPOLocalGroup - Collects Local Admin information using GPO (Group Policy Objects)
            LoggedOn - Collects session information using privileged methods (needs admin!)
            ObjectProps - Collects node property information for users and computers
            Default - Collects Group Membership, Local Admin, Sessions, and Domain Trusts
            DcOnly - Collects Group Membership, ACLs, ObjectProps, Trusts, Containers, and GPO Admins
            All - Collect all data except GPOLocalGroup and LoggedOn

        This can be a list of comma seperated valued as well to run multiple collection methods!

    .PARAMETER Domain

        Specifies the domain to enumerate. If not specified, will enumerate the current
        domain your user context specifies.

    .PARAMETER SearchForest

        Expands data collection to include all domains in the forest. 

    .PARAMETER LdapFilter

        Append this ldap filter to the search filter to further filter the results enumerated

    .PARAMETER Stealth

        Use stealth collection options, will sacrifice data quality in favor of much reduced
        network impact

    .PARAMETER SkipGCDeconfliction

        Skip's Global Catalog deconfliction during session enumeration. This option
        can result in more inaccuracy in data.

    .PARAMETER ComputerFile

        A file containing a list of computers to enumerate. This option can only be used with the following Collection Methods:
        Session, SessionLoop, LocalGroup, ComputerOnly, LoggedOn

    .PARAMETER ExcludeDC

        Exclude domain controllers from session queries. Useful for ATA environments which detect this behavior

    .PARAMETER OU

        Limit enumeration to this OU. Takes a DistinguishedName.
        Ex. OU=Domain Controllers,DC=testlab,DC=local

    .PARAMETER DomainController

        Specify which Domain Controller to request data from. Defaults to closest DC using Site Names

    .PARAMETER LdapPort

        Override the port used to connect to LDAP

    .PARAMETER SecureLdap

        Uses LDAPs instead of unencrypted LDAP on port 636

    .PARAMETER IgnoreLdapCert

        Ignores the certificate for LDAP

    .PARAMETER LDAPUser

        User to connect to LDAP with

    .PARAMETER LDAPPass

        Password for user you are connecting to LDAP with

    .PARAMETER DisableKerbSigning

        Disables Kerberos Signing on requests.
    
    .PARAMETER Threads

        Specifies the number of threads to use during enumeration (Default 20)

    .PARAMETER PingTimeout

        Specifies timeout for ping requests to computers in milliseconds (Default 750)

    .PARAMETER SkipPing

        Skip all ping checks for computers. This option will most likely be slower as
        API calls will be made to all computers regardless of being up
        Use this option if ping is disabled on the network for some reason

    .PARAMETER LoopDelay

        Amount of time to wait between session enumeration loops in minutes. This option
        should be used in conjunction with the SessionLoop enumeration method. 
        (Default 300 seconds)

    .PARAMETER MaxLoopTime

        Length of time to run looped session collection. Format: 0d0h0m0s or any variation of this format.
        Use in conjunction with -c SessionLoop
        Default will loop for two hours

    .PARAMETER Throttle

        Time in milliseconds to throttle after each request to a computer

    .Parameter Jitter

        Percentage jitter to apply to throttle

    .PARAMETER JSONFolder

        Folder to export JSONs too (Defaults to current directory)

    .PARAMETER JSONPrefix

        Prefix to add to your JSON Files (Default "")

    .PARAMETER NoZip

        Don't compress JSON files and remove them from disk

    .PARAMETER EncryptZip

        Add a random password to the zip file

    .PARAMETER ZipFileName

        Change the filename for the zip file

    .PARAMETER RandomFilenames

        Randomize output filenames

    .PARAMETER PrettyJson

        Output pretty JSON at the cost of file size

    .PARAMETER CacheFile

        Filename for the cache used by bloodhound. (Default <B64 machine sid>.bin)
    
    .PARAMETER Invalidate

        Invalidate the cache and build a new one

    .PARAMETER SaveCache
        
        Whether to save the cache file. Set this to false to disable writing it to disk

    .PARAMETER Interval

        Interval to display progress during enumeration in milliseconds (Default 30000)

    .PARAMETER Verbose

        Enable verbose output mode. Will print a lot!

    .PARAMETER OverrideUser

        Overrides the 'current' user to filter it out of session enumeration.
        Useful when you're using runas, as the user will be detected incorrectly
        
    .EXAMPLE

        PS C:\> Invoke-BloodHound

        Executes the default collection options and exports JSONs to the current directory, compresses the data to a zip file,
        and then removes the JSON files from disk

    .EXAMPLE
        
        PS C:\> Invoke-BloodHound -CollectionMethod SessionLoop -LoopDelay 60 -MaxLoopTime 10
    
        Executes session collection in a loop. Will wait 1 minute after each run to continue collection
        and will continue running for 10 minutes after which the script will exit

    .EXAMPLE

        PS C:\> Invoke-BloodHound -CollectionMethod All
    
        Runs ACL, ObjectProps, Container, and Default collection methods, compresses the data to a zip file,
        and then removes the JSON files from disk

    .EXAMPLE (Opsec!)

        PS C:\> Invoke-BloodHound -CollectionMethod DCOnly --NoSaveCache --RandomFilenames --EncryptZip
    
        Run LDAP only collection methods (Groups, Trusts, ObjectProps, ACL, Containers, GPO Admins) without outputting the cache file to disk. 
        Randomizes filenames of the JSON files and the zip file and adds a password to the zip file
    #>

    param(
        [String[]]
        $CollectionMethod = [string[]] @('Default'),

        [Switch]
        $SearchForest,

        [String]
        $Domain,

        [String]
        $LdapFilter,

        [Switch]
        $Stealth,

        [Switch]
        $SkipGCDeconfliction,

        [Switch]
        $ExcludeDC,

        [String]
        $ComputerFile,

        [String]
        $OU,

        [string]
        $DomainController,

        [int]
        $LdapPort,

        [Switch]
        $SecureLdap,

        [Switch]
        $IgnoreLdapCert,

        [String]
        $LDAPUser,

        [String]
        $LDAPPass,

        [Switch]
        $DisableKerbSigning,

        [ValidateRange(1,50)]
        [Int]
        $Threads = 10,

        [ValidateRange(50,1500)]
        [int]
        $PingTimeout = 250,

        [Switch]
        $SkipPing,

        [ValidateRange(1,50000000)]
        [int]
        $LoopDelay,

        [ValidatePattern('[0-9]+[smdh]')]
        [string]
        $MaxLoopTime,

        [ValidateRange(0,100)]
        [int]
        $Jitter,

        [int]
        $Throttle,

        [ValidateScript({ Test-Path -Path $_ })]
        [String]
        $JSONFolder = $(Get-Location),

        [ValidateNotNullOrEmpty()]
        [String]
        $JSONPrefix,

        [Switch]
        $NoZip,

        [Switch]
        $EncryptZip,

        [String]
        $ZipFileName,

        [Switch]
        $RandomFilenames,

        [Switch]
        $PrettyJson,
        

        [String]
        [ValidateNotNullOrEmpty()]
        $CacheFile,

        [Switch]
        $Invalidate,

        [Switch]
        $NoSaveCache,

        [ValidateRange(500,60000)]
        [int]
        $StatusInterval,

        [String]
        $OverrideUser,

        [Switch]
        $Verbose
    )

    $vars = New-Object System.Collections.Generic.List[System.Object]

    $vars.Add("-c")
    foreach ($cmethod in $CollectionMethod){
        $vars.Add($cmethod);
    }
    
    if ($Domain){
        $vars.Add("-d");
        $vars.Add($Domain);
    }

    if ($SearchForest){
        $vars.Add("-s");
    }

    if ($Stealth){
        $vars.Add("--Stealth")
    }

    if ($SkipGCDeconfliction){
        $vars.Add("--SkipGCDeconfliction")
    }

    if ($ExcludeDC){
        $vars.Add("--ExcludeDC")
    }

    if ($ComputerFile){
        $vars.Add("--ComputerFile");
        $vars.Add($ComputerFile);
    }

    if ($OU){
        $vars.Add("--OU");
        $vars.Add($OU);
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

    if ($IgnoreLdapCert){
        $vars.Add("--IgnoreLdapCert");
    }

    if ($LDAPUser){
        $vars.Add("--LDAPUser");
        $vars.Add($LDAPUser);
    }

    if ($LDAPPass){
        $vars.Add("--LDAPPass");
        $vars.Add($LDAPPass);
    }

    if ($DisableKerbSigning){
        $vars.Add("--DisableKerbSigning");
    }

    if ($Threads){
        $vars.Add("-t")
        $vars.Add($Threads)
    }

    if ($PingTimeout){
        $vars.Add("--PingTimeout")
        $vars.Add($PingTimeout)
    }

    if ($SkipPing){
        $vars.Add("--SkipPing");
    }

    if ($LoopDelay){
        $vars.Add("--LoopDelay")
        $vars.Add($LoopDelay)
    }

    if ($MaxLoopTime){
        $vars.Add("--MaxLoopTime")
        $vars.Add($MaxLoopTime)
    }

    if ($Throttle){
        $vars.Add("--Throttle");
        $vars.Add($Throttle);
    }

    if ($Jitter){
        $vars.Add("--Jitter");
        $vars.Add($Jitter);
    }

    if ($JSONFolder){
        $vars.Add("--JSONFolder");
        $vars.Add($JSONFolder);
    }

    if ($JSONPrefix){
        $vars.Add("--JSONPrefix");
        $vars.Add($JSONPrefix);
    }

    if ($NoZip){
        $vars.Add("--NoZip");
    }

    if ($EncryptZip){
        $vars.Add("--EncryptZip");
    }

    if ($ZipFileName){
        $vars.Add("--ZipFileName");
        $vars.Add($ZipFileName);
    }

    if ($RandomFilenames){
        $vars.Add("--RandomFilenames");
    }

    if ($PrettyJson){
        $vars.Add("--PrettyJson");
    }

    if ($CacheFile){
        $vars.Add("--CacheFile");
        $vars.Add($CacheFile);
    }

    if ($Invalidate){
        $vars.Add("--Invalidate");
    }

    if ($NoSaveCache){
        $vars.Add("--NoSaveCache");
    }

    if ($LdapFilter){
        $vars.Add("--LdapFilter");
        $vars.Add($LdapFilter);
    }

    if ($Verbose){
        $vars.Add("-v")
    }

    if ($StatusInterval){
        $vars.Add("--StatusInterval")
        $vars.Add($StatusInterval)
    }

    if ($OverrideUser){
        $vars.Add("--OverrideUser")
        $vars.Add($OverrideUser)
    }

    $passed = [string[]]$vars.ToArray()

    #ENCODEDCONTENTHERE
}
