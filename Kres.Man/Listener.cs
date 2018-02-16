using System;
using System.Linq;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Text;
using Newtonsoft.Json;

namespace Kres.Man
{
    internal class Listener
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(typeof(Listener));
        private Thread tLoop;

        [Mapping("health")]
        public object getHealthHandler(string postData)
        {
            if (
                (tLoop == null) || (tLoop != null && !tLoop.IsAlive) ||
                (UdpServer.tUdpLoop == null) || (UdpServer.tUdpLoop != null && !UdpServer.tUdpLoop.IsAlive) ||
                (CoreClient.tCoreLoop == null) || (CoreClient.tCoreLoop != null && !CoreClient.tCoreLoop.IsAlive) ||
                (KresUpdater.tKresLoop == null) || (KresUpdater.tKresLoop != null && !KresUpdater.tKresLoop.IsAlive)
                )
            {
                log.Info($"Health check failed.");
                log.Info($"tLoop = {tLoop}, UdpServer.tUdpLoop = {UdpServer.tUdpLoop}, CoreClient.tCoreLoop = {CoreClient.tCoreLoop}, KresUpdater.tKresLoop = {KresUpdater.tKresLoop}");

                return new HttpException("Kres.Man is unhealthy.", HttpStatusCode.InternalServerError);
            }

            log.Info($"Health check passed.");

            return null;
        }


        [Mapping("pushswapcaches")]
        public object pushSwapCaches(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.swapcache, buffer);
        }

        [Mapping("pushfreecaches")]
        public object pushFreeCaches(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.swapfreebuffers, buffer);
        }

        [Mapping("pushdomaincrcbuffer")]
        public object pushDomainCrcBuffer(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.domainCrcBuffer, buffer); 
        }

        [Mapping("pushdomainaccuracybuffer")]
        public object pushDomainAccuracyBuffer(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.domainAccuracyBuffer, buffer); 
        }

        [Mapping("pushdomainflagsbuffer")]
        public object pushDomainFlagsBuffer(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.domainFlagsBuffer, buffer); 
        }

        [Mapping("pushiprangefrombuffer")]
        public object pushIPRangeFromBuffer(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.iprangeipfrom, buffer);
        }

        [Mapping("pushiprangetobuffer")]
        public object pushIPRangeToBuffer(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.iprangeipto, buffer);
        }

        [Mapping("pushiprangeidentitybuffer")]
        public object pushIPRangeIdentityBuffer(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.iprangeidentity, buffer);
        }

        [Mapping("pushiprangepolicybuffer")]
        public object pushIPRangePolicyBuffer(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.iprangepolicyid, buffer);
        }

        [Mapping("pushpolicyidbuffer")]
        public object pushPolicyIDBuffer(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.policyid, buffer);
        }

        [Mapping("pushpolicystrategybuffer")]
        public object pushPolicyStrategyBuffer(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.policystrategy, buffer);
        }

        [Mapping("pushpolicyauditbuffer")]
        public object pushPolicyAuditBuffer(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.policyaudit, buffer);
        }

        [Mapping("pushpolicyblockbuffer")]
        public object pushPolicyBlockBuffer(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.policyblock, buffer);
        }

        [Mapping("pushcustomlistidentitkbuffer")]
        public object pushCustomListIdentityBuffer(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.identitybuffer, buffer);
        }

        [Mapping("pushcustomlistwhitelistbuffer")]
        public object pushCustomListWhitelistBuffer(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.identitybufferwhitelist, buffer);
        }

        [Mapping("pushcustomlistblacklistbuffer")]
        public object pushCustomListBlacklistBuffer(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.identitybufferblacklist, buffer);
        }

        [Mapping("bypass")]
        public object Bypass(string postdata, string ipaddress, string domainToWhitelist)
        {
            string identity = ipaddress.GetHashCode().ToString("X");
            

            IPAddress ip;
            if (!IPAddress.TryParse(ipaddress, out ip))
            {
                return new Exception($"unable to parse ip address {ipaddress}.");
            }

            var bytes = ip.GetAddressBytes();
            BigMath.Int128 intip;
            if (bytes.Length == 4)
            {
                intip = new BigMath.Int128(0, BitConverter.ToUInt32(bytes, 0));
            }
            else if (bytes.Length == 16)
            {
                intip = new BigMath.Int128(BitConverter.ToUInt64(bytes, 0), BitConverter.ToUInt64(bytes, 8));
            }
            else
            {
                return new Exception($"unable to parse ip address {ipaddress}.");
            }
            var kip = Kres.Man.Models.Int128.Convert(intip);

            var ipranges = CacheLiveStorage.CoreCache.IPRanges.ToList();
            var customlists = CacheLiveStorage.CoreCache.CustomLists.ToList();
            ipranges.Add(new Models.CacheIPRange()
            {
                Identity = identity,
                IpFrom = kip,
                IpTo = kip,
                PolicyId = 0
            });
            var item = customlists.FirstOrDefault(t => string.Compare(t.Identity, identity, StringComparison.OrdinalIgnoreCase) == 0);
            if (item == null)
            {
                item = new Models.CacheCustomList()
                {
                    Identity = identity,
                    WhiteList = new List<string>() { domainToWhitelist },
                    BlackList = new List<string>()
                };
            }
            else
            {
                if (item.WhiteList.Contains(domainToWhitelist))
                {
                    log.Info($"Identity {identity} has {domainToWhitelist} already whitelisted.");
                    return null;
                }

                var list = item.WhiteList.ToList();
                list.Add(domainToWhitelist);
                item.WhiteList = list;
            }
            customlists.RemoveAll(t => string.Compare(t.Identity, identity, StringComparison.OrdinalIgnoreCase) == 0);
            customlists.Add(item);

            log.Info($"Identity {identity} now has {domainToWhitelist} whitelisted.");

            CacheLiveStorage.CoreCache.IPRanges = ipranges;
            CacheLiveStorage.CoreCache.CustomLists = customlists;

            KresUpdater.UpdateNow();

            return null;
        }



        private static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = Convert.FromBase64String(base64EncodedData);
            return Encoding.UTF8.GetString(base64EncodedBytes);
        }

        private void ThreadProc()
        {
            log.Info("Starting Listener thread.");

            try
            {
                while (true)
                {
                    log.Info($"Starting listener.");
                    HttpListener listener = new HttpListener();

                    listener.Prefixes.Add(Configuration.GetListener());
                    listener.Start();
                    while (true)
                    {
                        log.Info($"Waiting for listener context.");
                        HttpListenerContext ctx = listener.GetContext();

                        ThreadPool.QueueUserWorkItem((_) =>
                        {
                            try
                            {
                                string methodName = ctx.Request.Url.Segments[1].Replace("/", "");
                                string[] strParams = ctx.Request.Url
                                                        .Segments
                                                        .Skip(2)
                                                        .Select(s => s.Replace("/", ""))
                                                        .ToArray();

                                var method = this.GetType()
                                                    .GetMethods()
                                                    .Where(mi => mi.GetCustomAttributes(true).Any(attr => attr is Mapping && ((Mapping)attr).Map == methodName))
                                                    .First();

                                var args = method.GetParameters().Skip(1).Select((p, i) => Convert.ChangeType(strParams[i], p.ParameterType));
                                var @params = new object[args.Count() + 1];

                                var inLength = ctx.Request.ContentLength64;
                                log.Info($"Content len = {inLength}.");
                                var inBuffer = new byte[4096];
                                var buffer = new byte[inLength];
                                int totalBytesRead = 0;
                                int bytesRead = 0;
                                while (true)
                                {
                                    bytesRead = ctx.Request.InputStream.Read(inBuffer, 0, inBuffer.Length);
                                    if (bytesRead == 0 || bytesRead == -1)
                                    {
                                        log.Info($"Nothing to read len = {totalBytesRead}.");
                                        break;
                                    }

                                    Array.Copy(inBuffer, 0, buffer, totalBytesRead, bytesRead);
                                    totalBytesRead += bytesRead;

                                    if (totalBytesRead == inLength)
                                    {
                                        log.Info($"Read finished to read len = {totalBytesRead}.");
                                        break;
                                    }
                                }

                                var content = Encoding.UTF8.GetString(buffer);
                                @params[0] = content;
                                Array.Copy(args.ToArray(), 0, @params, 1, args.Count());

                                log.Info($"Invoking {method.Name}");
                                try
                                {
                                    var ret = method.Invoke(this, @params);
                                    var retstr = JsonConvert.SerializeObject(ret);

                                    var outBuffer = Encoding.UTF8.GetBytes(retstr);
                                    ctx.Response.ContentLength64 = outBuffer.LongLength;
                                    ctx.Response.OutputStream.Write(outBuffer, 0, outBuffer.Length);
                                    ctx.Response.OutputStream.Close();
                                }
                                catch (HttpException ex)
                                {
                                    log.Warn($"{ex}");

                                    ctx.Response.StatusCode = (int)ex.Status;
                                    ctx.Response.ContentType = "text/plain";

                                    var outBuffer = Encoding.UTF8.GetBytes(ex.Message);
                                    ctx.Response.ContentLength64 = outBuffer.LongLength;
                                    ctx.Response.OutputStream.Write(outBuffer, 0, outBuffer.Length);
                                    ctx.Response.OutputStream.Close();
                                }
                            }
                            catch (Exception ex)
                            {
                                log.Error($"{ex}");
                            }
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                tLoop = null;

                log.Fatal($"{ex}");
            }
        }
        

        public void Listen()
        {
            tLoop = new Thread(ThreadProc);
            tLoop.Start();

                
        }
    }
}
