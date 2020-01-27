namespace SharpHound3.Enums
{
    /// <summary>
    /// Enum representing return codes from NETAPI calls
    /// </summary>
    internal enum NetApiStatus
    {
        NERR_Success = 0,
        ERROR_MORE_DATA = 234,
        ERROR_NO_BROWSER_SERVERS_FOUND = 6118,
        ERROR_INVALID_LEVEL = 124,
        ERROR_ACCESS_DENIED = 5,
        ERROR_INVALID_PARAMETER = 87,
        ERROR_NOT_ENOUGH_MEMORY = 8,
        ERROR_NETWORK_BUSY = 54,
        ERROR_BAD_NETPATH = 53,
        ERROR_NO_NETWORK = 1222,
        ERROR_INVALID_HANDLE_STATE = 1609,
        ERROR_EXTENDED_ERROR = 1208,
        NERR_BASE = 2100,
        NERR_UNKNOWNDEVDIR = (NERR_BASE + 16),
        NERR_DUPLICATESHARE = (NERR_BASE + 18),
        NERR_BUFFTOOSMALL = (NERR_BASE + 23)
    }
}
