using System;

namespace SharpHound3.Enums
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
        PSRemote,
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
        PSRemote = 1 << 9,
        SPNTargets = 1 << 10,
        Container = 1 << 11,
        GPOLocalGroup = 1 << 12,
        DCOnly = 1 << 13,
        LocalGroups = DCOM | RDP | LocalAdmin | PSRemote
    }
}
