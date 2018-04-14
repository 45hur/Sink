using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text;
using System.Threading;
using System.Net;
using System.Net.Http;

using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json;

namespace Kres.Man
{
    internal class CoreClient
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(typeof(CoreClient));
        public static Thread tCoreLoop;
        private static ConcurrentDictionary<Tuple<BigMath.Int128, BigMath.Int128>, Models.CacheIPRange> CacheRadius {get; set;} 

        private static void ThreadProc()
        {
            log.Info("Starting CoreClient thread.");

            while (true)
            {
                try
                {
                    GetCoreCache();
                }
                catch (Exception ex)
                {
                    tCoreLoop = null;
                    log.Fatal($"{ex}");
                }

                Thread.Sleep(60000);
            }
        }

        private static bool ValidateRemoteCertificate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors error)
        {
            if (error == SslPolicyErrors.RemoteCertificateChainErrors)
            {
                var cert2 = cert as X509Certificate2;
                if (cert2 != null)
                {
                    if (string.Compare(cert2.Thumbprint, "E05B94180B1C02A89BAF451BF0F6A286AC529342", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private static void GetCoreCache()
        {
            log.Info("GetCoreCache()");

            string host = Configuration.GetCoreUrl();
            string certName = Configuration.GetPfxPath();
            string password = Configuration.GetPfxPassword();

            var clientHandler = new HttpClientHandler() { ClientCertificateOptions = ClientCertificateOption.Manual };
            X509Certificate2 clientCertificate = new X509Certificate2(certName, password);
            clientHandler.ClientCertificates.Add(clientCertificate);
            var myClient = new HttpClient(clientHandler);
            myClient.DefaultRequestHeaders
              .Accept
              .Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/x-protobuf"));

            var req = new HttpRequestMessage(HttpMethod.Get, host)
            {
                Version = new Version(2, 0)
            };
            req.Headers.Add("x-resolver-id", "13");

            using (var response = myClient.SendAsync(req).GetAwaiter().GetResult())
            {
                using (var stream = response.Content.ReadAsStreamAsync().GetAwaiter().GetResult())
                {
                    CacheLiveStorage.CoreCache = ProtoBuf.Serializer.Deserialize<Models.Cache>(stream);
                }
            }
        }

        public static void Start()
        {
            tCoreLoop = new Thread(ThreadProc);
            tCoreLoop.Start();
        }

    }
}
