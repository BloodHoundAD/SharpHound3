using System;
using System.Collections.Generic;
using System.Linq;
using CommandLine;
using SharpHound3.Enums;

namespace SharpHound3
{
    public class Options
    {
        public static Options Instance { get; set; }

        //Collection Options
        [Option('c', "CollectionMethod", Default = new[] { "Default"})]
        public IEnumerable<string> CollectionMethods { get; set; }

        [Option(HelpText = "Use Stealth Targetting/Enumeration Options", Default = false)]
        public bool Stealth { get; set; }

        [Option(HelpText = "Loop LoggedOn/Session Collection", Default = false)]
        public bool Loop { get; set; }

        [Option(HelpText = "Specify domain for enumeration", Default = null)]
        public string Domain { get; set; }

        [Option(HelpText = "Search all domains in the forest", Default = false)]
        public bool SearchForest { get; set; }

        //Output Options
        [Option(HelpText = "Folder to output files too", Default = ".")]
        public string OutputDirectory { get; set; }

        [Option(HelpText = "Prefix for output files", Default = null)]
        public string OutputPrefix { get; set; }

        [Option(HelpText = "Output pretty(formatted) JSON", Default = false)]
        public bool PrettyJson { get; set; }

        [Option(HelpText = "Filename for the cache file (defaults to b64 of machine sid)", Default = null)]
        public string CacheFilename { get; set; }

        [Option(HelpText = "Randomize filenames for JSON files", Default = false)]
        public bool RandomizeFilenames { get; set; }

        [Option(HelpText = "Filename for the Zip file", Default = null)]
        public string ZipFilename { get; set; }

        [Option(HelpText = "Don't save cache to disk. Caching will still be done in memory", Default = false)]
        public bool NoSaveCache { get; set; }

        [Option(HelpText = "Encrypt zip file using a random password", Default = false)]
        public bool EncryptZip { get; set; }

        [Option(HelpText = "Don't zip JSON files")]
        public bool NoZip { get; set; }

        [Option(HelpText = "Invalidate and rebuld the cache")]
        public bool InvalidateCache { get; set; }

        //Connection Options
        [Option(HelpText = "Custom LDAP Filter to append to the search. Use this to filter collection", Default = null)]
        public string LdapFilter { get; set; }

        [Option(HelpText = "Domain Controller to connect too. Specifying this value can result in data loss", Default = null)]
        public string DomainController { get; set; }

        [Option(HelpText = "Port LDAP is running on. Defaults to 389/636 for LDAPS", Default = 0)]
        public int LdapPort { get; set; }

        [Option(HelpText = "Connect to LDAPS (LDAP SSL) instead of regular LDAP", Default = false)]
        public bool SecureLDAP { get; set; }

        [Option(HelpText = "Disables Kerberos Signing/Sealing making LDAP traffic viewable", Default = false)]
        public bool DisableKerberosSigning { get; set; }

        [Option(HelpText = "Ignore LDAP certificates. Sometimes useful when connecting via LDAPS")]
        public bool IgnoreLdapCertificate { get; set; }

        //Enumeration Options
        [Option(HelpText = "Skip SMB port checks when connecting to computers", Default = false)]
        public bool SkipPing { get; set; }

        [Option(HelpText="Timeout for SMB port check", Default = 1000)]
        public int PingTimeout { get; set; }

        [Option(HelpText = "Exclude domain controllers from enumeration (useful to avoid Microsoft ATP/ATA)", Default = false)]
        public bool ExcludeDomainControllers { get; set; }

        [Option(HelpText = "Throttle requests to computers in milliseconds")]
        public int Throttle { get; set; }

        [Option(HelpText = "Jitter between requests to computers")]
        public int Jitter { get; set; }

        [Option(HelpText = "Override username to filter for NetSessionEnum", Default = null)]
        public string OverrideUserName { get; set; }

        [Option(HelpText = "Disable remote registry check in LoggedOn collection", Default = false)]
        public bool NoRegistryLoggedOn { get; set; }

        [Option(HelpText = "Dump success/failures related to computer enumeration to a CSV file", Default = false)]
        public bool DumpComputerStatus { get; set; }

        [Option(HelpText = "Override DNS name for API calls", Default = null)]
        public string RealDNSName { get; set; }

        [Option(HelpText = "Collect all LDAP properties from objects instead of a subset during ObjectProps", Default = false)]
        public bool CollectAllProperties { get; set; }

        //Output Options
        [Option(HelpText = "Interval in which to display status in milliseconds", Default = 30000)]
        public int StatusInterval { get; set; }

        [Option('v', HelpText = "Enable Verbose Output", Default = false)]
        public bool Verbose { get; set; }

        //Internal Options
        public CollectionMethodResolved ResolvedCollectionMethods { get; set; }

        public string CurrentUserName { get; set; }

        internal bool ResolveCollectionMethods()
        {
            // If the length is 1, either we only got 1 collection method, or we got this value from the powershell script and we need to split
            var collMethodArray = CollectionMethods.ToArray();
            if (collMethodArray.Length == 1)
            {
                collMethodArray = collMethodArray[0].Split(',');
            }

            var resolved = CollectionMethodResolved.None;
            foreach (var baseString in collMethodArray)
            {
                CollectionMethodOptions option = CollectionMethodOptions.None;
                try
                {
                    option =
                        (CollectionMethodOptions) Enum.Parse(typeof(CollectionMethodOptions), baseString, true);
                }
                catch
                {
                    Console.WriteLine($"Failed to parse Collection Method {baseString}.");
                    return false;
                }

                switch (option)
                {
                    case CollectionMethodOptions.All:
                        resolved = resolved | CollectionMethodResolved.ACL | CollectionMethodResolved.Container |
                                   CollectionMethodResolved.Group | CollectionMethodResolved.LocalGroups |
                                   CollectionMethodResolved.ObjectProps | CollectionMethodResolved.Sessions |
                                   CollectionMethodResolved.Trusts | CollectionMethodResolved.LoggedOn |
                                   CollectionMethodResolved.SPNTargets;
                        break;
                    case CollectionMethodOptions.DCOnly:
                        resolved = resolved | CollectionMethodResolved.ACL | CollectionMethodResolved.Container |
                                   CollectionMethodResolved.Group | CollectionMethodResolved.ObjectProps |
                                   CollectionMethodResolved.Trusts | CollectionMethodResolved.DCOnly |
                                   CollectionMethodResolved.GPOLocalGroup;
                        break;
                    case CollectionMethodOptions.Group:
                        resolved |= CollectionMethodResolved.Group;
                        break;
                    case CollectionMethodOptions.Sessions:
                        resolved |= CollectionMethodResolved.Sessions;
                        break;
                    case CollectionMethodOptions.LoggedOn:
                        resolved |= CollectionMethodResolved.LoggedOn;
                        break;
                    case CollectionMethodOptions.Trusts:
                        resolved |= CollectionMethodResolved.Trusts;
                        break;
                    case CollectionMethodOptions.ACL:
                        resolved |= CollectionMethodResolved.ACL;
                        break;
                    case CollectionMethodOptions.ObjectProps:
                        resolved |= CollectionMethodResolved.ObjectProps;
                        break;
                    case CollectionMethodOptions.RDP:
                        resolved |= CollectionMethodResolved.RDP;
                        break;
                    case CollectionMethodOptions.DCOM:
                        resolved |= CollectionMethodResolved.DCOM;
                        break;
                    case CollectionMethodOptions.LocalAdmin:
                        resolved |= CollectionMethodResolved.LocalAdmin;
                        break;
                    case CollectionMethodOptions.PSRemote:
                        resolved |= CollectionMethodResolved.PSRemote;
                        break;
                    case CollectionMethodOptions.SPNTargets:
                        resolved |= CollectionMethodResolved.SPNTargets;
                        break;
                    case CollectionMethodOptions.Container:
                        resolved |= CollectionMethodResolved.Container;
                        break;
                    case CollectionMethodOptions.GPOLocalGroup:
                        resolved |= CollectionMethodResolved.GPOLocalGroup;
                        break;
                    case CollectionMethodOptions.LocalGroup:
                        resolved |= CollectionMethodResolved.LocalGroups;
                        break;
                    case CollectionMethodOptions.Default:
                        resolved = resolved | CollectionMethodResolved.ACL | CollectionMethodResolved.Container |
                                   CollectionMethodResolved.Group | CollectionMethodResolved.LocalGroups |
                                   CollectionMethodResolved.ObjectProps | CollectionMethodResolved.Sessions |
                                   CollectionMethodResolved.Trusts | CollectionMethodResolved.SPNTargets;
                        break;
                    default:
                        throw new ArgumentOutOfRangeException();
                }
            }

            ResolvedCollectionMethods = resolved;

            return true;
        }

        internal bool IsComputerCollectionSet()
        {
            return (ResolvedCollectionMethods & CollectionMethodResolved.Sessions) != 0 ||
                   (ResolvedCollectionMethods & CollectionMethodResolved.LocalAdmin) != 0 ||
                   (ResolvedCollectionMethods & CollectionMethodResolved.RDP) != 0 ||
                   (ResolvedCollectionMethods & CollectionMethodResolved.DCOM) != 0 ||
                   (ResolvedCollectionMethods & CollectionMethodResolved.PSRemote) != 0 ||
                   (ResolvedCollectionMethods & CollectionMethodResolved.LoggedOn) != 0;
        }
    }
}
