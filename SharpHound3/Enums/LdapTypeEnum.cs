using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace SharpHound3.Enums
{
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
