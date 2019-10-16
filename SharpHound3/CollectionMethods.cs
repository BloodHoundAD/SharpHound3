using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHound3
{
    public enum CollectionMethodOptions
    {
        None,
        Group,
        Sessions,
        LoggedOn,
        Trusts,
        ACL,
        ObjectProps,
        RDP,
        DCOM,
        LocalAdmin,
        SPNTargets,
        Container,
        GPOLocalGroup,
        LocalGroup,
        Default,
        DCOnly,
        All
    }

    [Flags]
    public enum CollectionMethodResolved
    {
        None = 0,
        Group = 1,
        Sessions = 1 << 1,
        LoggedOn = 1 << 2,
        Trusts = 1 << 3,
        ACL = 1 << 4,
        ObjectProps = 1 << 5,
        RDP = 1 << 6,
        DCOM = 1 << 7,
        LocalAdmin = 1 << 8,
        SPNTargets = 1 << 9,
        Container = 1 << 10,
        GPOLocalGroup = 1 << 11,
        DCOnly = 1 << 12
    }
}
