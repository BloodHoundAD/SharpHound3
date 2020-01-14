using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;
using SharpHound3.Enums;
using SharpHound3.JSON;
using SharpHound3.LdapWrappers;

namespace SharpHound3.Tasks
{
    internal class ObjectPropertyTasks
    {
        private static readonly DateTime WindowsEpoch = new DateTime(1970, 1, 1);

        internal static async Task<LdapWrapper> ResolveObjectProperties(LdapWrapper wrapper)
        {
            var result = wrapper.SearchResult;
            wrapper.Properties.Add("description", result.GetProperty("description"));

            if (wrapper is Domain domain)
            {
                ParseDomainProperties(domain);
            }else if (wrapper is Computer computer)
            {
                await ParseComputerProperties(computer);
            }else if (wrapper is User user)
            {
                await ParseUserProperties(user);
            }else if (wrapper is GPO gpo)
            {
                ParseGPOProperties(gpo);
            }else if (wrapper is OU ou)
            {
                ParseOUProperties(ou);
            }else if (wrapper is Group group)
            {
                ParseGroupProperties(group);
            }

            return wrapper;
        }

        private static void ParseGroupProperties(Group wrapper)
        {
            var result = wrapper.SearchResult;

            var adminCount = result.GetProperty("admincount");
            if (adminCount != null)
            {
                var a = int.Parse(adminCount);
                wrapper.Properties.Add("admincount", a != 0);
            }
            else
            {
                wrapper.Properties.Add("admincount", false);
            }
        }   

        private static void ParseGPOProperties(GPO wrapper)
        {
            var result = wrapper.SearchResult;

            wrapper.Properties.Add("gpcpath", result.GetProperty("gpcfilesyspath"));
        }

        private static void ParseOUProperties(OU wrapper)
        {
            //var result = wrapper.SearchResult;
        }

        private static async Task ParseComputerProperties(Computer wrapper)
        {
            var result = wrapper.SearchResult;
            var userAccountControl = result.GetProperty("useraccountcontrol");

            var enabled = true;
            var trustedToAuth = false;
            var unconstrained = false;
            if (int.TryParse(userAccountControl, out var baseFlags))
            {
                var uacFlags = (UacFlags)baseFlags;
                enabled = (uacFlags & UacFlags.AccountDisable) == 0;
                trustedToAuth = (uacFlags & UacFlags.TrustedToAuthForDelegation) != 0;
                unconstrained = (uacFlags & UacFlags.TrustedForDelegation) != 0;    
            }

            wrapper.Properties.Add("enabled", enabled);
            wrapper.Properties.Add("unconstraineddelegation", unconstrained);

            var trustedToAuthComputers = new List<string>();
            // Parse Allowed To Delegate
            if (trustedToAuth)
            {
                var delegates = result.GetPropertyAsArray("msds-AllowedToDelegateTo");
                wrapper.Properties.Add("allowedtodelegate", delegates);
                // For each computer thats in this array, try and turn it into a SID
                foreach (var computerName in delegates)
                {
                    var resolvedHost = await ResolutionHelpers.ResolveHostToSid(computerName, wrapper.Domain);
                    trustedToAuthComputers.Add(resolvedHost);
                }
            }
            wrapper.AllowedToDelegate = trustedToAuthComputers.Distinct().ToArray();

            var allowedToAct = result.GetPropertyAsBytes("msDS-AllowedToActOnBehalfOfOtherIdentity");

            var allowedToActPrincipals = new List<GenericMember>();

            if (allowedToAct != null)
            {
                var securityDescriptor = new ActiveDirectorySecurity();
                securityDescriptor.SetSecurityDescriptorBinaryForm(allowedToAct);
                foreach (ActiveDirectoryAccessRule ace in securityDescriptor.GetAccessRules(true, true,
                    typeof(SecurityIdentifier)))
                {
                    var sid = ace.IdentityReference.Value;
                    LdapTypeEnum type;
                    if (CommonPrincipal.GetCommonSid(sid, out var principal))
                    {
                        type = principal.Type;
                        sid = Helpers.ConvertCommonSid(sid, wrapper.Domain);
                    }
                    else
                    {
                        type = await ResolutionHelpers.LookupSidType(sid,wrapper.Domain);
                    }

                    allowedToActPrincipals.Add(new GenericMember
                    {
                        MemberType = type,
                        MemberId = sid
                    });
                }
            }

            wrapper.AllowedToAct = allowedToActPrincipals.Distinct().ToArray();
            
            wrapper.Properties.Add("serviceprincipalnames", result.GetPropertyAsArray("serviceprincipalname"));

            wrapper.Properties.Add("lastlogontimestamp", ConvertToUnixEpoch(result.GetProperty("lastlogontimestamp")));
            wrapper.Properties.Add("pwdlastset", ConvertToUnixEpoch(result.GetProperty("pwdlastset")));
            

            var os = result.GetProperty("operatingsystem");
            var sp = result.GetProperty("operatingsystemservicepack");

            if (sp != null)
            {
                os = $"{os} {sp}";
            }

            wrapper.Properties.Add("operatingsystem", os);
        }

        private static void ParseDomainProperties(Domain wrapper)
        {
            var result = wrapper.SearchResult;
            if (!int.TryParse(result.GetProperty("msds-behavior-version"), out var level)) level = -1;
            string func;
            switch (level)
            {
                case 0:
                    func = "2000 Mixed/Native";
                    break;
                case 1:
                    func = "2003 Interim";
                    break;
                case 2:
                    func = "2003";
                    break;
                case 3:
                    func = "2008";
                    break;
                case 4:
                    func = "2008 R2";
                    break;
                case 5:
                    func = "2012";
                    break;
                case 6:
                    func = "2012 R2";
                    break;
                case 7:
                    func = "2016";
                    break;
                default:
                    func = "Unknown";
                    break;
            }
            wrapper.Properties.Add("functionallevel", func);
        }

        private static async Task ParseUserProperties(User wrapper)
        {
            var result = wrapper.SearchResult;

            // Start with UAC properties
            var userAccountControl = result.GetProperty("useraccountcontrol");
            var enabled = true;
            var trustedToAuth = false;
            var sensitive = false;
            var dontReqPreAuth = false;
            var passwdNotReq = false;
            var unconstrained = false;
            if (int.TryParse(userAccountControl, out var baseFlags))
            {
                var uacFlags = (UacFlags) baseFlags;
                enabled = (uacFlags & UacFlags.AccountDisable) == 0;
                trustedToAuth = (uacFlags & UacFlags.TrustedToAuthForDelegation) != 0;
                sensitive = (uacFlags & UacFlags.NotDelegated) != 0;
                dontReqPreAuth = (uacFlags & UacFlags.DontReqPreauth) != 0;
                passwdNotReq = (uacFlags & UacFlags.PasswordNotRequired) != 0;
                unconstrained = (uacFlags & UacFlags.TrustedForDelegation) != 0;
            }

            wrapper.Properties.Add("dontreqpreauth", dontReqPreAuth);
            wrapper.Properties.Add("passwordnotreqd", passwdNotReq);
            wrapper.Properties.Add("unconstraineddelegation", unconstrained);
            wrapper.Properties.Add("sensitive", sensitive);
            wrapper.Properties.Add("enabled", enabled);

            var trustedToAuthComputers = new List<string>();
            // Parse Allowed To Delegate
            if (trustedToAuth)
            {
                var delegates = result.GetPropertyAsArray("msds-AllowedToDelegateTo");
                wrapper.Properties.Add("allowedtodelegate", delegates);

                //Try to resolve each computer to a SID
                foreach (var computerName in delegates)
                {
                    var resolvedHost = await ResolutionHelpers.ResolveHostToSid(computerName, wrapper.Domain);
                    trustedToAuthComputers.Add(resolvedHost);
                }
            }
            wrapper.AllowedToDelegate = trustedToAuthComputers.Distinct().ToArray();

            //Grab time based properties
            wrapper.Properties.Add("lastlogon", ConvertToUnixEpoch(result.GetProperty("lastlogon")));
            wrapper.Properties.Add("lastlogontimestamp", ConvertToUnixEpoch(result.GetProperty("lastlogontimestamp")));
            wrapper.Properties.Add("pwdlastset", ConvertToUnixEpoch(result.GetProperty("pwdlastset")));

            var servicePrincipalNames = result.GetPropertyAsArray("serviceprincipalname");
            wrapper.Properties.Add("serviceprincipalnames", servicePrincipalNames);
            wrapper.Properties.Add("hasspn", servicePrincipalNames.Length > 0);

            wrapper.Properties.Add("displayname", result.GetProperty("displayname"));
            wrapper.Properties.Add("email", result.GetProperty("mail"));
            wrapper.Properties.Add("title", result.GetProperty("title"));
            wrapper.Properties.Add("homedirectory", result.GetProperty("homedirectory"));
            wrapper.Properties.Add("userpassword", result.GetProperty("userpassword"));

            var adminCount = result.GetProperty("admincount");
            if (adminCount != null)
            {
                var a = int.Parse(adminCount);
                wrapper.Properties.Add("admincount", a != 0);
            }
            else
            {
                wrapper.Properties.Add("admincount", false);
            }
        }

        private static long ConvertToUnixEpoch(string ldapTime)
        {
            if (ldapTime == null)
                return -1;

            var time = long.Parse(ldapTime);
            if (time == 0)
                return 0;

            long toReturn;

            try
            {
                toReturn = (long)Math.Floor(DateTime.FromFileTimeUtc(time).Subtract(WindowsEpoch).TotalSeconds);
            }
            catch
            {
                toReturn = -1;
            }

            return toReturn;
        }
    }
}
