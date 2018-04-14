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

        private static async void ThreadProc()
        {
            log.Info("Starting UDP Server thread.");

            using (UdpClient listener = new UdpClient(Configuration.GetUdpPort()))
            {
                IPEndPoint groupEP = new IPEndPoint(IPAddress.Any, 1813);
                try
                {
                    while (true)
                    {
                        var receivedResult = await listener.ReceiveAsync();
                        Task.Run(() => { ProcessResult(receivedResult); });
                    }
                }
                catch (Exception ex)
                {
                    log.Fatal(ex);
                }
                finally
                {
                    listener.Close();
                    tUdpLoop = null;
                }
            }
        }

        private static void ProcessResult(UdpReceiveResult receivedResult)
        {
            try
            {
                var receivedPacket = new FP.Radius.RadiusPacket(receivedResult.Buffer);
                if (receivedPacket.Valid)
                {
                    var ipaddress = receivedPacket.Attributes.Where(t => t.Type == FP.Radius.RadiusAttributeType.FRAMED_IP_ADDRESS).First();
                    var sessionid = ASCIIEncoding.ASCII.GetString(receivedPacket.Attributes.Where(t => t.Type == FP.Radius.RadiusAttributeType.ACCT_SESSION_ID).First().Data);

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
