using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Reflection;

using Newtonsoft.Json;

namespace Kres.Man
{
    public class PassiveDNSEnricher
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private Thread tLoop;

        public string filename_in { get
            {
                return Configuration.GetPassiveDnsSource();
            }
        } 
        public string filename_out
        {
            get
            {
                return Configuration.GetPassiveDnsDestination();
            }
        }

        public void Listen()
        {
            tLoop = new Thread(ThreadProc);
            tLoop.Start();
        }

        public void ThreadProc()
        {
            //DebugPrepareUDPTest();

            var processedLines = 0;
            while (true)
            {
                Thread.Sleep(5000);

                try
                {
                    if (CacheLiveStorage.UdpCache == null)
                    {
                        log.Info("Waiting for UDP Cache");
                        continue;
                    }

                    var ipRange = CacheLiveStorage.UdpCache.Select(t => t.Value).ToList();

                    using (var filein = File.OpenRead(filename_in))
                    {
                        using (var sr = new StreamReader(filein))
                        {
                            var i = 0;
                            try
                            {
                                while (i++ < processedLines)
                                {
                                    while (sr.Peek() >= 0)
                                    {
                                        var line = sr.ReadLine();
                                    }
                                }
                            }
                            catch
                            {
                                log.Debug("PassiveDNS log was changed.");
                                processedLines = 0;
                                continue;
                            }

                            using (var fileout = File.AppendText(filename_out))
                            { 
                                while (sr.Peek() >= 0)
                                {
                                    var line = sr.ReadLine();
                                    dynamic reader = JsonConvert.DeserializeObject(line);

                                    IPAddress ipaddress = IPAddress.Parse(reader.client.ToString());
                                    var addrbytes = ipaddress.GetAddressBytes().Reverse().ToArray();
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

                                    var ip = new BigMath.Int128(addr.Hi, addr.Low);
                                    var range = ipRange.Where(t => t.BintFrom >= ip && t.BintTo <= ip).FirstOrDefault();

                                    var strippedLine = line.Substring(0, line.Length - 1);
                                    var newLine = string.Format("{0},identity=\"{1}\"}}", strippedLine, (range == null) ? "unknown" : range.Identity);
                                    fileout.WriteLine(newLine);
                                    processedLines++;
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    processedLines = 0;
                    log.ErrorFormat("PassiveDNS error: {0}", ex);
                }
            }
        }

        private void DebugPrepareUDPTest()
        {
            var ipaddress = IPAddress.Parse("80.83.66.2");
            var addrbytes = ipaddress.GetAddressBytes().Reverse().ToArray();
            var addr = new Models.Int128();
            if (addrbytes.Length == 4)
            {
                addr.Hi = 0;
                addr.Low = BitConverter.ToUInt32(addrbytes, 0);
            }

            var addresstext = new BigMath.Int128(addr.Hi, addr.Low).ToString();
            var addbytes2 = ASCIIEncoding.ASCII.GetBytes(addresstext);

            var item = new Models.CacheIPRange()
            {
                Created = DateTime.UtcNow,
                Identity = "identity1",
                Proto_IpFrom = addbytes2,
                Proto_IpTo = addbytes2,
                PolicyId = 0
            };

            CacheLiveStorage.UdpCache = new System.Collections.Concurrent.ConcurrentDictionary<string, Models.CacheIPRange>();
            CacheLiveStorage.UdpCache.AddOrUpdate("stationid1", item, (key, oldValue) => item);
        }
    }
}
