using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text;
using System.Threading;
using System.Net;

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


            X509Certificate2Collection certificates = new X509Certificate2Collection();
            certificates.Import(certName, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);

            ServicePointManager.ServerCertificateValidationCallback = (a, b, c, d) => true;
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(host);
            req.ServerCertificateValidationCallback += ValidateRemoteCertificate;
            req.AllowAutoRedirect = true;
            req.ClientCertificates = certificates;
            req.Method = "GET";
            req.ContentType = "application/x-protobuf";
            req.Headers["x-resolver-id"] = "13";
            //string postData = "";
            //byte[] postBytes = Encoding.UTF8.GetBytes(postData);
            //req.ContentLength = postBytes.Length;

            //var postStream = req.GetRequestStream();
            //postStream.Write(postBytes, 0, postBytes.Length);
            //postStream.Flush();
            //postStream.Close();

            using (var response = req.GetResponseAsync().Result)
            {
                using (var stream = response.GetResponseStream())
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
