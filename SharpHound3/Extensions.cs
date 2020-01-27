using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.Principal;
using SharpHound3.Enums;

namespace SharpHound3
{
    internal static class Extensions
    {
        public static void PrintEntry(this SearchResultEntry searchResultEntry)
        {
            foreach (var propertyName in searchResultEntry.Attributes.AttributeNames)
            {
                var property = propertyName.ToString();
                Console.WriteLine(property);
                Console.WriteLine(searchResultEntry.GetProperty(property));
            }
        }


        #region SearchResultEntry
        public static string GetProperty(this SearchResultEntry searchResultEntry, string property)
        {
            if (!searchResultEntry.Attributes.Contains(property))
                return null;

            var collection = searchResultEntry.Attributes[property];
            var lookups = collection.GetValues(typeof(string));
            if (lookups.Length == 0)
                return null;

            if (!(lookups[0] is string prop) || prop.Length == 0)
                return null;

            return prop;
        }

        public static string GetSid(this SearchResultEntry searchResultEntry)
        {
            try
            {
                if (!searchResultEntry.Attributes.Contains("objectsid")) return null;
            }
            catch (ArgumentNullException)
            {
                return null;
            }

            object[] s;
            try
            {
                s = searchResultEntry.Attributes["objectsid"].GetValues(typeof(byte[]));
            }
            catch (NotSupportedException)
            {
                return null;
            }

            if (s.Length == 0)
                return null;

            if (!(s[0] is byte[] sidBytes) || sidBytes.Length == 0)
                return null;

            try
            {
                var sid = new SecurityIdentifier(sidBytes, 0);
                return sid.Value.ToUpper();
            }
            catch (ArgumentNullException)
            {
                return null;
            }
        }

        public static string[] GetPropertyAsArray(this SearchResultEntry searchResultEntry, string property)
        {
            if (!searchResultEntry.Attributes.Contains(property))
                return new string[0];

            var values = searchResultEntry.Attributes[property];
            var strings = values.GetValues(typeof(string));

            if (!(strings is string[] result))
                return null;

            return result;
        }

        public static byte[][] GetPropertyAsArrayOfBytes(this SearchResultEntry searchResultEntry, string property)
        {
            var list = new List<byte[]>();
            if (!searchResultEntry.Attributes.Contains(property))
                return list.ToArray();

            var values = searchResultEntry.Attributes[property];
            var bytes = values.GetValues(typeof(byte[]));

            if (!(bytes is byte[][] result))
                return null;

            return result;
        }

        public static byte[] GetPropertyAsBytes(this SearchResultEntry searchResultEntry, string property)
        {
            if (!searchResultEntry.Attributes.Contains(property))
                return null;

            var collection = searchResultEntry.Attributes[property];
            var lookups = collection.GetValues(typeof(byte[]));
            if (lookups.Length == 0)
                return null;

            if (!(lookups[0] is byte[] bytes) || bytes.Length == 0)
                return null;

            return bytes;
        }

        public static string GetObjectIdentifier(this SearchResultEntry searchResultEntry)
        {
            if (!searchResultEntry.Attributes.Contains("objectsid") &&
                !searchResultEntry.Attributes.Contains("objectguid"))
                return null;

            if (searchResultEntry.Attributes.Contains("objectsid"))
            {
                return searchResultEntry.GetSid();
            }

            if (searchResultEntry.Attributes.Contains("objectguid"))
            {
                var guidBytes = searchResultEntry.GetPropertyAsBytes("objectguid");

                return new Guid(guidBytes).ToString().ToUpper();
            }

            return null;
        }

        /// <summary>
        /// Extension method to determine the type of a SearchResultEntry.
        /// Requires objectsid, samaccounttype, objectclass
        /// </summary>
        /// <param name="searchResultEntry"></param>
        /// <returns></returns>
        public static LdapTypeEnum GetLdapType(this SearchResultEntry searchResultEntry)
        {
            var objectId = searchResultEntry.GetObjectIdentifier();
            if (objectId == null)
                return LdapTypeEnum.Unknown;

            if (CommonPrincipal.GetCommonSid(objectId, out var commonPrincipal))
                return commonPrincipal.Type;

            var objectType = LdapTypeEnum.Unknown;
            var samAccountType = searchResultEntry.GetProperty("samaccounttype");
            //Its not a common principal. Lets use properties to figure out what it actually is
            if (samAccountType != null)
            {
                if (samAccountType == "805306370")
                    return LdapTypeEnum.Unknown;

                objectType = Helpers.SamAccountTypeToType(samAccountType);
            }
            else
            {
                var objectClasses = searchResultEntry.GetPropertyAsArray("objectClass");
                if (objectClasses == null)
                {
                    objectType = LdapTypeEnum.Unknown;
                }
                else if (objectClasses.Contains("groupPolicyContainer"))
                {
                    objectType = LdapTypeEnum.GPO;
                }
                else if (objectClasses.Contains("organizationalUnit"))
                {
                    objectType = LdapTypeEnum.OU;
                }
                else if (objectClasses.Contains("domain"))
                {
                    objectType = LdapTypeEnum.Domain;
                }
            }

            //Override GMSA object type
            if (searchResultEntry.GetPropertyAsBytes("msds-groupmsamembership") != null)
                objectType = LdapTypeEnum.User;

            return objectType;
        }

        #endregion

        public static bool HasFlag(this Enum self, Enum test)
        {
            if (self == null || test == null)
            {
                return false;
            }

            try
            {
                var temp = Convert.ToInt32(self);
                var num = Convert.ToInt32(test);
                return (temp & num) == num;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
