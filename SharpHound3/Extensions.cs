using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

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
        /// <summary>
        /// Extension method to determine the type of a SearchResultEntry.
        /// Requires objectsid, samaccounttype, objectclass
        /// </summary>
        /// <param name="searchResultEntry"></param>
        /// <returns></returns>
        public static LdapTypeEnum GetLdapType(this SearchResultEntry searchResultEntry)
        {
            var objectSid = searchResultEntry.GetSid();
            if (CommonPrincipal.GetCommonSid(objectSid, out var commonPrincipal))
            {
                return commonPrincipal.Type;
            }

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
            return objectType;
        }

        public static string GetProperty(this SearchResultEntry searchResultEntry, string property)
        {
            if (!searchResultEntry.Attributes.Contains(property))
                return null;

            return searchResultEntry.Attributes[property][0].ToString();
        }

        public static string GetSid(this SearchResultEntry searchResultEntry)
        {
            if (!searchResultEntry.Attributes.Contains("objectsid"))
                return null;

            //objectsid can sometimes be either a string or a byte array. Just AD things
            var s = searchResultEntry.Attributes["objectsid"][0];
            switch (s)
            {
                case byte[] b:
                    return new SecurityIdentifier(b, 0).ToString();
                case string st:
                    return new SecurityIdentifier(Encoding.ASCII.GetBytes(st), 0).ToString();
            }

            return null;
        }

        public static string[] GetPropertyAsArray(this SearchResultEntry searchResultEntry, string property)
        {
            if (!searchResultEntry.Attributes.Contains(property))
                return new string[0];

            var values = searchResultEntry.Attributes[property];

            var propArray = new string[values.Count];

            for (var i = 0; i < values.Count; i++)
                propArray[i] = values[i].ToString();

            return propArray;
        }

        public static byte[] GetPropertyAsBytes(this SearchResultEntry searchResultEntry, string property)
        {
            if (!searchResultEntry.Attributes.Contains(property))
                return null;
            return searchResultEntry.Attributes[property][0] as byte[];
        }

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
