using System.Collections.Generic;
using CommandLine;

namespace SharpHound3
{
    public class Options
    {
        public static Options Instance { get; set; }

        //Collection Options
        [Option('c', "CollectionMethod", Default = new[] { SharpHound3.CollectionMethodOptions.Default})]
        public IEnumerable<CollectionMethodOptions> CollectionMethods { get; set; }

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

        [Option(HelpText = "Exclude domain controllers from enumeration (useful to avoid Microsoft ATP/ATA)", Default = false)]
        public bool ExcludeDomainControllers { get; set; }

        [Option(HelpText = "Throttle requests to computers in milliseconds")]
        public int Throttle { get; set; }

        [Option(HelpText = "Jitter between requests to computers")]
        public int Jitter { get; set; }

        //Internal Options
        public CollectionMethodResolved ResolvedCollectionMethods { get; set; }
    }
}
