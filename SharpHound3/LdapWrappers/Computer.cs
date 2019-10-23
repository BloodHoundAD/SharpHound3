using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using SharpHound3.JSON;

namespace SharpHound3.LdapWrappers
{
    internal class Computer : LdapWrapper
    {
        internal Computer(SearchResultEntry entry) : base(entry)
        {
            AllowedToAct = new string[0];
            AllowedToDelegate = new string[0];
            Sessions = new Session[0];
            PingFailed = false;
        }

        [JsonIgnore]
        public string SamAccountName { get; set; }

        public string[] AllowedToDelegate { get; set; }

        public string[] AllowedToAct { get; set; }

        public string PrimaryGroupSid { get; set; }

        public Session[] Sessions { get; set; }

        public GroupMember[] LocalAdmins { get; set; }

        public GroupMember[] RemoteDesktopUsers { get; set; }

        public GroupMember[] DcomUsers { get; set; }

        public GroupMember[] PSRemoteUsers { get; set; }

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
