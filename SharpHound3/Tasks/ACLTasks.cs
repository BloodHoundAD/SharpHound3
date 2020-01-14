using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading.Tasks;
using SharpHound3.Enums;
using SharpHound3.JSON;
using SharpHound3.LdapWrappers;

namespace SharpHound3.Tasks
{
    internal static class ACLTasks
    {
        private static readonly Dictionary<Type, string> BaseGuids;
        private const string AllGuid = "00000000-0000-0000-0000-000000000000";

        static ACLTasks()
        {
            BaseGuids = new Dictionary<Type, string>
            {
                {typeof(User), "bf967aba-0de6-11d0-a285-00aa003049e2"},
                {typeof(Computer), "bf967a86-0de6-11d0-a285-00aa003049e2"},
                {typeof(Group), "bf967a9c-0de6-11d0-a285-00aa003049e2"},
                {typeof(Domain), "19195a5a-6da0-11d0-afd3-00c04fd930c9"},
                {typeof(GPO), "f30e3bc2-9ff0-11d1-b603-0000f80367c1"},
                {typeof(OU), "bf967aa5-0de6-11d0-a285-00aa003049e2"}
            };
        }

        internal static async Task<LdapWrapper> ProcessDACL(LdapWrapper wrapper)
        {
            var aces = new List<ACL>();
            var ntSecurityDescriptor = wrapper.SearchResult.GetPropertyAsBytes("ntsecuritydescriptor");

            //If the NTSecurityDescriptor is null, something screwy is happening. Nothing to process here, so continue in the pipeline
            if (ntSecurityDescriptor == null)
                return wrapper;

            var descriptor = new ActiveDirectorySecurity();
            descriptor.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);

            var ownerSid = FilterAceSids(descriptor.GetOwner(typeof(SecurityIdentifier)).Value);
            if (ownerSid != null)
            {
                var (finalSid, type) = await ResolutionHelpers.ResolveSidAndGetType(ownerSid, wrapper.Domain);
                if (finalSid != null)
                {
                    aces.Add(new ACL
                    {
                        PrincipalSID = finalSid,
                        RightName = "Owner",
                        AceType = "",
                        PrincipalType = type,
                        IsInherited = false
                    });
                }
            }

            foreach (ActiveDirectoryAccessRule ace in descriptor.GetAccessRules(true,
                true, typeof(SecurityIdentifier)))
            {
                //Ignore Null Aces
                if (ace == null)
                    continue;
                //Ignore deny aces
                if (ace.AccessControlType == AccessControlType.Deny)
                    continue;

                //Check if the ACE actually applies to our object based on the object type
                if (!IsAceInherited(ace, BaseGuids[wrapper.GetType()]))
                    continue;

                var principalSid = FilterAceSids(ace.IdentityReference.Value);

                if (principalSid == null)
                    continue;

                var (finalSid, type) = await ResolutionHelpers.ResolveSidAndGetType(principalSid, wrapper.Domain);

                var rights = ace.ActiveDirectoryRights;
                var objectAceType = ace.ObjectType.ToString();
                var isInherited = ace.IsInherited;

                if (rights.HasFlag(ActiveDirectoryRights.GenericAll))
                {
                    if (objectAceType == AllGuid || objectAceType == "")
                    {
                        aces.Add(new ACL
                        {
                            PrincipalSID = finalSid,
                            RightName = "GenericAll",
                            AceType = "",
                            PrincipalType = type,
                            IsInherited = isInherited
                        });
                    }
                    //GenericAll includes every other right, and we dont want to duplicate. So continue in the loop
                    continue;
                }

                //WriteDacl and WriteOwner are always useful to us regardless of object type
                if (rights.HasFlag(ActiveDirectoryRights.WriteDacl))
                {
                    aces.Add(new ACL
                    {
                        PrincipalSID = finalSid,
                        AceType = "",
                        RightName = "WriteDacl",
                        PrincipalType = type,
                        IsInherited = isInherited
                    });
                }

                if (rights.HasFlag(ActiveDirectoryRights.WriteOwner))
                {
                    aces.Add(new ACL
                    {
                        RightName = "WriteOwner",
                        AceType = "",
                        PrincipalSID = finalSid,
                        PrincipalType = type,
                        IsInherited = isInherited
                    });
                }

                //Process object specific ACEs
                //Extended rights apply to Users, Domains, Computers
                if (rights.HasFlag(ActiveDirectoryRights.ExtendedRight))
                {
                    if (wrapper is Domain)
                    {
                        switch (objectAceType)
                        {
                            case "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2":
                                aces.Add(new ACL
                                {
                                    AceType = "GetChanges",
                                    RightName = "ExtendedRight",
                                    PrincipalSID = finalSid,
                                    PrincipalType = type,
                                    IsInherited = isInherited
                                });
                                break;
                            case "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2":
                                aces.Add(new ACL
                                {
                                    AceType = "GetChangesAll",
                                    RightName = "ExtendedRight",
                                    PrincipalSID = finalSid,
                                    PrincipalType = type,
                                    IsInherited = isInherited
                                });
                                break;
                            case AllGuid:
                            case "":
                                aces.Add(new ACL
                                {
                                    AceType = "All",
                                    RightName = "ExtendedRight",
                                    PrincipalSID = finalSid,
                                    PrincipalType = type,
                                    IsInherited = isInherited
                                });
                                break;
                        }
                    }else if (wrapper is User)
                    {
                        switch (objectAceType)
                        {
                            case "00299570-246d-11d0-a768-00aa006e0529":
                                aces.Add(new ACL
                                {
                                    AceType = "User-Force-Change-Password",
                                    PrincipalSID = finalSid,
                                    RightName = "ExtendedRight",
                                    PrincipalType = type,
                                    IsInherited = isInherited
                                });
                                break;
                            case AllGuid:
                            case "":
                                aces.Add(new ACL
                                {
                                    AceType = "All",
                                    PrincipalSID = finalSid,
                                    RightName = "ExtendedRight",
                                    PrincipalType = type,
                                    IsInherited = isInherited
                                });
                                break;
                        }
                    }else if (wrapper is Computer)
                    {
                        Helpers.GetDirectorySearcher(wrapper.Domain).GetAttributeFromGuid(objectAceType, out var mappedGuid);
                        if (wrapper.SearchResult.GetProperty("ms-mcs-admpwdexpirationtime") != null)
                        {
                            if (objectAceType == AllGuid || objectAceType == "")
                            {
                                aces.Add(new ACL
                                {
                                    AceType = "All",
                                    RightName = "ExtendedRight",
                                    PrincipalSID = finalSid,
                                    PrincipalType = type,
                                    IsInherited = isInherited
                                });
                            }else if (mappedGuid != null && mappedGuid == "ms-Mcs-AdmPwd")
                            {
                                aces.Add(new ACL
                                {
                                    AceType = "",
                                    RightName = "ReadLAPSPassword",
                                    PrincipalSID = finalSid,
                                    PrincipalType = type,
                                    IsInherited = isInherited
                                });
                            }
                        }
                    }
                }

                //PropertyWrites apply to Groups, User, Computer
                //GenericWrite encapsulates WriteProperty, so we need to check them at the same time to avoid duplicate edges
                if (rights.HasFlag(ActiveDirectoryRights.GenericWrite) ||
                    rights.HasFlag(ActiveDirectoryRights.WriteProperty))
                {
                    if (objectAceType == AllGuid || objectAceType == "")
                    {
                        aces.Add(new ACL
                        {
                            AceType = "",
                            RightName = "GenericWrite",
                            PrincipalSID = finalSid,
                            PrincipalType = type,
                            IsInherited = isInherited
                        });
                    }

                    if (wrapper is User)
                    {
                        if (objectAceType == "f3a64788-5306-11d1-a9c5-0000f80367c1")
                        {
                            aces.Add(new ACL
                            {
                                AceType = "WriteSPN",
                                RightName = "WriteProperty",
                                PrincipalSID = finalSid,
                                PrincipalType = type,
                                IsInherited = isInherited
                            });
                        }
                    }else if (wrapper is Group)
                    {
                        if (objectAceType == "bf9679c0-0de6-11d0-a285-00aa003049e2")
                        {
                            aces.Add(new ACL
                            {
                                AceType = "AddMember",
                                RightName = "WriteProperty",
                                PrincipalSID = finalSid,
                                PrincipalType = type,
                                IsInherited = isInherited
                            });
                        }
                    }else if (wrapper is Computer)
                    {
                        if (objectAceType == "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79")
                        {
                            aces.Add(new ACL
                            {
                                AceType = "AllowedToAct",
                                RightName = "WriteProperty",
                                PrincipalSID = finalSid,
                                PrincipalType = type,
                                IsInherited = isInherited
                            });
                        }
                    }
                }
            }

            wrapper.Aces = aces.Distinct().ToArray();
            return wrapper;
        }

        /// <summary>
        /// Helper function to determine if an ACE actually applies to the object through inheritance
        /// </summary>
        /// <param name="ace"></param>
        /// <param name="guid"></param>
        /// <returns></returns>
        private static bool IsAceInherited(ObjectAccessRule ace, string guid)
        {
            //Check if the ace is inherited
            var isInherited = ace.IsInherited;

            //The inheritedobjecttype needs to match the guid of the object type being enumerated or the guid for All
            var inheritedType = ace.InheritedObjectType.ToString();
            isInherited = isInherited && (inheritedType == AllGuid || inheritedType == guid);

            //Special case for Exchange
            //If the ACE is not Inherited and is not an inherit-only ace, then it's set by exchange for reasons
            if (!isInherited && (ace.PropagationFlags & PropagationFlags.InheritOnly) != PropagationFlags.InheritOnly &&
                !ace.IsInherited)
            {
                isInherited = true;
            }

            //Return our isInherited value
            return isInherited;
        }

        /// <summary>
        /// Applies pre-processing to the SID on the ACE converting sids as necessary
        /// </summary>
        /// <param name="sid"></param>
        /// <param name="objectDomain"></param>
        /// <returns></returns>
        private static string FilterAceSids(string sid)
        { 
            //Ignore Local System/Creator Owner/Principal Self
            if (sid == "S-1-5-18" || sid == "S-1-3-0" || sid == "S-1-5-10")
            {
                return null;
            }

            return sid.ToUpper();
        }
    }
}
