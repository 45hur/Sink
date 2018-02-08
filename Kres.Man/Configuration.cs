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

        internal static int GetRedeliveryInterval()
        {
            return Convert.ToInt32(GetValue("redelivery_interval"));
        }
        internal static int GetUdpPort()
        {
            return Convert.ToInt32(GetValue("udpport"));
        }
        internal static string GetCoreUrl()
        {
            return GetValue("core");
        }
        internal static string GetCoreToken()
        {
            return GetValue("coretoken");
        }
        internal static string GetKres()
        {
            return GetValue("kres");
        }


    }
}
