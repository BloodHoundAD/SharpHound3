using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace SharpHound3.JSON
{
    public class Trust
    {   
        [JsonProperty]
        internal string TargetDomainSid { get; set; }
        [JsonProperty]
        internal bool IsTransitive { get; set; }
        [JsonProperty]
        internal TrustDirection TrustDirection { get; set; }
        [JsonProperty]
        internal TrustType TrustType { get; set; }
        [JsonProperty]
        internal bool SidFilteringEnabled { get; set; }
        [JsonProperty]
        internal string TargetDomainName { get; set; }

    }

    internal enum TrustDirection
    {
        Disabled = 0,
        Inbound = 1,
        Outbound = 2,
        Bidirectional = 3
    }

    internal enum TrustType
    {
        ParentChild,
        CrossLink,
        Forest,
        External,
        Unknown
    }
}
