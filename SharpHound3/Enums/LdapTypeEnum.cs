using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace SharpHound3.Enums
{
    /// <summary>
    /// Enum representing the possible object types.
    /// Converts to string representation when using JSON.NET
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum LdapTypeEnum
    {
        User,
        Computer,
        Group,
        GPO,
        Domain,
        OU,
        Unknown
    }
}
