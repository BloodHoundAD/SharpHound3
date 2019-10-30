using System.DirectoryServices.Protocols;
using Newtonsoft.Json;
using SharpHound3.JSON;

namespace SharpHound3.LdapWrappers
{
    internal class Computer : LdapWrapper
    {
        internal Computer(SearchResultEntry entry) : base(entry)
        {
            AllowedToAct = new GenericMember[0];
            AllowedToDelegate = new string[0];
            Sessions = new Session[0];
            PingFailed = false;
            LocalAdmins = new GenericMember[0];
            RemoteDesktopUsers = new GenericMember[0];
            DcomUsers = new GenericMember[0];
            PSRemoteUsers= new GenericMember[0];
        }

        [JsonIgnore]
        public string SamAccountName { get; set; }

        public string[] AllowedToDelegate { get; set; }

        public GenericMember[] AllowedToAct { get; set; }

        public string PrimaryGroupSid { get; set; }

        public Session[] Sessions { get; set; }

        public GenericMember[] LocalAdmins { get; set; }

        public GenericMember[] RemoteDesktopUsers { get; set; }

        public GenericMember[] DcomUsers { get; set; }

        public GenericMember[] PSRemoteUsers { get; set; }

        [JsonIgnore]
        public bool PingFailed { get; set; }

        [JsonIgnore]
        public string APIName
        {
            get
            {
                if (Options.Instance.RealDNSName != null)
                {
                    return $"{SamAccountName}.{Options.Instance.RealDNSName}";
                }

                return DisplayName;
            }
        }
    }
}
