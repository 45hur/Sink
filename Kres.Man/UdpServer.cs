using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Threading;


namespace Kres.Man
{
    internal class UdpServer
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private const int listenPort = 11000;
        public static Thread tUdpLoop;

        private static void ThreadProc()
        {
            log.Info("Starting Radius UDP Server thread.");

            var port = Configuration.GetUdpPort();
            while (true)
            {
                using (var listener = new UdpClient(port, AddressFamily.InterNetwork))
                {
                    var groupEP = new IPEndPoint(IPAddress.Any, 0);
                    try
                    {
                        while (true)
                        {
                            var receivedResult = listener.Receive(ref groupEP);
                            ProcessResult(receivedResult);
                        }

                    }
                    catch (Exception ex)
                    {
                        log.Fatal(ex);
                    }
                    finally
                    {
                        listener.Close();
                    }
                }
            }
        }

        private static void ProcessResult(byte[] receivedResult)
        {
            try
            {
                var receivedPacket = new FP.Radius.RadiusPacket(receivedResult);
                if (receivedPacket.Valid)
                {
                    var ipaddress = receivedPacket.Attributes.Where(t => t.Type == FP.Radius.RadiusAttributeType.FRAMED_IP_ADDRESS).First().Value;
                    var sessionid = ASCIIEncoding.ASCII.GetString(receivedPacket.Attributes.Where(t => t.Type == FP.Radius.RadiusAttributeType.ACCT_SESSION_ID).First().Data);

                    var addrbytes = IPAddress.Parse(ipaddress).GetAddressBytes();
                    var addr = new Models.Int128();
                    if (addrbytes.Length == 4)
                    {
                        addr.Hi = 0;
                        addr.Low = BitConverter.ToUInt32(addrbytes, 0);
                    }
                    else if (addrbytes.Length == 16)
                    {
                        addr.Hi = BitConverter.ToUInt64(addrbytes, 0);
                        addr.Low = BitConverter.ToUInt64(addrbytes, 8);
                    }

                    var addresstext = new BigMath.Int128(addr.Hi, addr.Low).ToString();
                    var addbytes2 = ASCIIEncoding.ASCII.GetBytes(addresstext);

                    var matchingCustomList = CacheLiveStorage.CoreCache.CustomLists.Where(t => string.Compare(t.Identity, sessionid, StringComparison.OrdinalIgnoreCase) == 0).FirstOrDefault();
                    var policyid = (matchingCustomList == null)
                        ? 0
                        : matchingCustomList.PolicyId;

                    var item = new Models.CacheIPRange()
                    {
                        Created = DateTime.UtcNow,
                        Identity = sessionid,
                        Proto_IpFrom = addbytes2,
                        Proto_IpTo = addbytes2,
                        PolicyId = policyid
                    };

                    CacheLiveStorage.UdpCache.AddOrUpdate(sessionid, item, (key, oldValue) => item);

                    log.Info($"Processed {ipaddress} for {sessionid}.");
                }
                else
                {
                    log.Info("Unable to process UDP packet.");
                }
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
        }

        public static void Listen()
        {
            tUdpLoop = new Thread(ThreadProc);
            tUdpLoop.Start();
        }
    }
}
