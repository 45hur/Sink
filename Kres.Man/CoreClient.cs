using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text;
using System.Threading;
using System.Net;

using Newtonsoft.Json;

namespace Kres.Man
{
    internal class CoreClient
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(typeof(CoreClient));
        public static Thread tCoreLoop;
        private static ConcurrentDictionary<Tuple<BigMath.Int128, BigMath.Int128>, Models.CacheIPRange> Cache2 {get; set;} 

        private static void ThreadProc()
        {
            log.Info("Starting CoreClient thread.");

            try
            {
                while (true)
                {
                    //GetCoreCache();

                    Thread.Sleep(60000);
                }
            }
            catch (Exception ex)
            {
                tCoreLoop = null;
                log.Fatal($"{ex}");
            }
        }

        private static void GetCoreCache()
        {
            log.Info("GetCoreCache()");
            var url = string.Format("{0}cache", Configuration.GetCoreUrl());

            var request = WebRequest.Create(url);
            request.Method = "GET";
            request.ContentType = "application/x-protobuf";

            request.Headers["X-Api-Authorization"] = Configuration.GetCoreToken();

            try
            {
                using (var response = request.GetResponseAsync().Result)
                {
                    using (var stream = response.GetResponseStream())
                    {
                        var cache = ProtoBuf.Serializer.Deserialize<Models.Cache>(stream);
                    }
                }
            }
            catch (Exception ex)
            {
                log.Error($"{ex}");
            }
        }

        public static void Start()
        {
            tCoreLoop = new Thread(ThreadProc);
            tCoreLoop.Start();
        }
    }
}
