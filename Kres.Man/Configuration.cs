using System;
using System.Collections.Generic;
using System.Text;

namespace Kres.Man
{
    internal class Configuration
    {
        private static string GetValue(string key)
        {
            var item = Environment.GetEnvironmentVariable(key);

            if (!string.IsNullOrEmpty(item))
                return item;

            var content = FileHelper.GetContent("appsettings.json");
            var json = Newtonsoft.Json.JsonConvert.DeserializeObject<Dictionary<string, string>>(content);
            return json[key];
        }

        internal static string GetServer()
        {
            return GetValue("server");
        }

        internal static string GetListener()
        {
            return GetValue("listener");
        }

        internal static string GetPublicListener()
        {
            return GetValue("publiclistener");
        }

        internal static int GetKresUpdateInterval()
        {
            return Convert.ToInt32(GetValue("kres_update_interval"));
        }
        internal static int GetUdpPort()
        {
            return Convert.ToInt32(GetValue("udpport"));
        }
        internal static string GetCoreUrl()
        {
            return GetValue("RESOLVERAPI_URL");
        }
        internal static string GetResolverId()
        {
            return GetValue("RESOLVER_ID");
        }
        internal static int GetResolverUpdateInterval()
        {
            return Convert.ToInt32(GetValue("RESOLVERAPI_UPDATE_INTERVAL_S"));
        }
        internal static string GetPfxPath()
        {
            return GetValue("pfxpath");
        }
        internal static string GetPfxPassword()
        {
            return GetValue("pfxpassword");
        }
        internal static string GetCoreToken()
        {
            return GetValue("coretoken");
        }
        internal static string GetKres()
        {
            return GetValue("kres");
        }
        internal static int GetMinPort()
        {
            return Convert.ToInt32(GetValue("kres_min_port"));
        }
        internal static int GetMaxPort()
        {
            return Convert.ToInt32(GetValue("kres_max_port"));
        }


    }
}
