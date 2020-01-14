using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using Microsoft.Win32;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using SharpHound3.Enums;

namespace SharpHound3
{
    internal class Cache
    {
        [JsonProperty]
        private ConcurrentDictionary<string, ResolvedPrincipal> _resolvedPrincipalDictionary;

        [JsonProperty]
        private ConcurrentDictionary<string, string[]> _globalCatalogDictionary;

        [JsonProperty]
        private ConcurrentDictionary<string, LdapTypeEnum> _sidTypeDictionary;

        [JsonProperty][JsonConverter(typeof(AccountCacheConverter))] private ConcurrentDictionary<UserDomainKey, ResolvedPrincipal> _resolvedAccountNameDictionary;

        [JsonIgnore]
        private readonly Mutex _bhMutex;

        [JsonIgnore]
        public static Cache Instance => CacheInstance;

        [JsonIgnore]
        private static Cache CacheInstance { get; set; }

        internal static void CreateInstance()
        {
            CacheInstance = new Cache();
            CacheInstance.LoadCache();
        }

        private Cache()
        {
            _bhMutex = new Mutex(false, $"MUTEX:{GetBase64MachineID()}");
        }

        internal bool GetResolvedAccount(UserDomainKey key, out ResolvedPrincipal value)
        {
            return _resolvedAccountNameDictionary.TryGetValue(key, out value);
        }

        internal bool GetResolvedDistinguishedName(string key, out ResolvedPrincipal value)
        {
            return _resolvedPrincipalDictionary.TryGetValue(key.ToUpper(), out value);
        }

        internal bool GetGlobalCatalogMatches(string key, out string[] sids)
        {
            return _globalCatalogDictionary.TryGetValue(key.ToUpper(), out sids);
        }

        internal bool GetSidType(string key, out LdapTypeEnum type)
        {
            return _sidTypeDictionary.TryGetValue(key.ToUpper(), out type);
        }

        internal void Add(UserDomainKey key, ResolvedPrincipal value)
        {
            _resolvedAccountNameDictionary.TryAdd(key, value);
        }
        
        internal void Add(string key, ResolvedPrincipal value)
        {
            _resolvedPrincipalDictionary.TryAdd(key.ToUpper(), value);
        }

        internal void Add(string key, string[] domains)
        {
            _globalCatalogDictionary.TryAdd(key.ToUpper(), domains);
        }

        internal void Add(string key, LdapTypeEnum type)
        {
            _sidTypeDictionary.TryAdd(key, type);
        }

        internal void LoadCache()
        {
            if (Options.Instance.InvalidateCache)
            {
                _globalCatalogDictionary = new ConcurrentDictionary<string, string[]>();
                _resolvedPrincipalDictionary = new ConcurrentDictionary<string, ResolvedPrincipal>();
                _sidTypeDictionary = new ConcurrentDictionary<string, LdapTypeEnum>();
                _resolvedAccountNameDictionary = new ConcurrentDictionary<UserDomainKey, ResolvedPrincipal>();
                Console.WriteLine("[-] Cache Invalidated: 0 Objects in Cache");
                Console.WriteLine();
                return;
            }

            var fileName = GetCacheFileName();

            if (!File.Exists(fileName))
            {
                _globalCatalogDictionary = new ConcurrentDictionary<string, string[]>();
                _resolvedPrincipalDictionary = new ConcurrentDictionary<string, ResolvedPrincipal>();
                _sidTypeDictionary = new ConcurrentDictionary<string, LdapTypeEnum>();
                _resolvedAccountNameDictionary = new ConcurrentDictionary<UserDomainKey, ResolvedPrincipal>();
                Console.WriteLine("[+] Cache File not Found: 0 Objects in cache");
                Console.WriteLine();
                return;
            }

            try
            {
                _bhMutex.WaitOne();
                var bytes = File.ReadAllBytes(fileName);
                var json = new UTF8Encoding(true).GetString(bytes);
                CacheInstance = JsonConvert.DeserializeObject<Cache>(json);
                Console.WriteLine($"[+] Cache File Found! Loaded {CacheInstance._resolvedPrincipalDictionary.Count + CacheInstance._globalCatalogDictionary.Count + CacheInstance._sidTypeDictionary.Count + CacheInstance._resolvedAccountNameDictionary.Count} Objects in cache");
                Console.WriteLine();
            }
            finally
            {
                _bhMutex.ReleaseMutex();
            }
        }

        private string GetCacheFileName()
        {
            var baseFilename = Options.Instance.CacheFilename ?? $"{GetBase64MachineID()}.bin";
            var finalFilename = Path.Combine(Options.Instance.OutputDirectory, baseFilename);

            return finalFilename;
        }

        internal void SaveCache()
        {
            if (Options.Instance.NoSaveCache)
            {
                return;
            }

            var jsonCache = new UTF8Encoding(true).GetBytes(JsonConvert.SerializeObject(CacheInstance));
            var finalFilename = GetCacheFileName();

            try
            {
                _bhMutex.WaitOne();
                using (var stream =
                    new FileStream(finalFilename, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    stream.Write(jsonCache, 0, jsonCache.Length);
                }
            }
            finally
            {
                _bhMutex.ReleaseMutex();
            }
        }

        private static string GetBase64MachineID()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Cryptography"))
                {
                    if (key == null)
                    {
                        return $"{Helpers.Base64(Environment.MachineName)}";
                    }

                    var guid = key.GetValue("MachineGuid") as string;
                    return Helpers.Base64(guid);
                }
            }
            catch
            {
                return $"{Helpers.Base64(Environment.MachineName)}";
            }
        }
    }

    public class ResolvedPrincipal
    {
        public string ObjectIdentifier { get; set; }
        public LdapTypeEnum ObjectType { get; set; }
    }

    internal class AccountCacheConverter : JsonConverter
    {
        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            IDictionary<UserDomainKey, ResolvedPrincipal> dict = (IDictionary<UserDomainKey, ResolvedPrincipal>)value;
            JObject obj = new JObject();
            foreach (var kvp in dict)
            {
                obj.Add(kvp.Key.ToString(), JToken.FromObject(kvp.Value));
            }
            obj.WriteTo(writer);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            JObject obj = JObject.Load(reader);
            IDictionary<UserDomainKey, ResolvedPrincipal> dict = (IDictionary<UserDomainKey, ResolvedPrincipal>)existingValue ?? new ConcurrentDictionary<UserDomainKey, ResolvedPrincipal>();
            foreach (var prop in obj.Properties())
            {
                var key = new UserDomainKey();
                var split = prop.Name.Split('\\');
                key.AccountDomain = split[0];
                key.AccountName = split[1];
                dict.Add(key, prop.Value.ToObject<ResolvedPrincipal>());
            }
            return dict;
        }

        public override bool CanConvert(Type objectType)
        {
            return typeof(IDictionary<UserDomainKey, string>).IsAssignableFrom(objectType);
        }
    }
}
