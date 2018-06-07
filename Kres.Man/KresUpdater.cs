using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Kres.Man
{
    enum bufferType
    {
        swapcache = 0,
        domainCrcBuffer = 1,
        domainAccuracyBuffer = 2,
        domainFlagsBuffer = 3,
        iprangeipfrom = 4,
        iprangeipto = 5,
        iprangeidentity = 6,
        iprangepolicyid = 7, 
        policyid = 8,
        policystrategy = 9,
        policyaudit = 10,
        policyblock = 11,
        identitybuffer = 12,
        identitybufferwhitelist = 13,
        identitybufferblacklist = 14,
        identitybufferpolicyid = 15,
        swapfreebuffers = 16,
    }

    struct TaskArgs
    {
        public int port;
        public bufferType buftype;
        public IEnumerable<byte[]> data;
    }

    class KresUpdater
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        public static Thread tKresLoop;
        private Listener listener;
        private static EventWaitHandle waitHandle = new EventWaitHandle(false, EventResetMode.AutoReset);
        private static EventWaitHandle updatedHandle = new EventWaitHandle(false, EventResetMode.AutoReset);
        private static bool updateSmallCaches = false;

        

        public static object Push(bufferType buftype, IEnumerable<byte[]> data)
        {
            log.Debug($"Push buftype {buftype}");

            List<Task> TaskList = new List<Task>();
            for (var port = Configuration.GetMinPort(); port < Configuration.GetMaxPort(); port++)
            {
                object arg = new TaskArgs()
                {
                    port = port,
                    buftype = buftype,
                    data = data
                };
                TaskList.Add(new TaskFactory().StartNew(new Action<object>((args) =>
                {
                    TaskJob(args);
                }), arg));

            }

            Task.WaitAll(TaskList.ToArray());

            return null;
        }



        private static int TaskJob(object args)
        {
            TaskArgs arg = (TaskArgs)args;
            int port = arg.port;
            bufferType buftype = arg.buftype;
            IEnumerable<byte[]> data = arg.data;
            try
            {
                using (var client = new TcpClient())
                {
                    client.Client.Connect(IPAddress.Parse(Configuration.GetKres()), port);

                    var messageType = (int)buftype;

                    //+ 8 bytes (= last crc64 bytes)
                    var header = BitConverter.GetBytes(messageType)             // 4 bytes -> message type
                        .Concat(BitConverter.GetBytes(data.Count()));            // 4 bytes -> how many buffers

                    var headerCrc = Crc64.Compute(0, header.ToArray());
                    header = header.Concat(BitConverter.GetBytes(headerCrc));   // 8 byte -> crc of this header

                    //log.Debug($"Get stream");
                    using (var stream = client.GetStream())
                    {
                        if (SendHeader(stream, header))
                        {
                            SendBuffers(stream, data);
                        }

                        //log.Debug($"Closing ip stream.");
                        stream.Flush();
                        stream.Close();
                    }
                    client.Close();

                    log.Debug($"Module {port} job {buftype} updated");

                }
            }
            catch (Exception ex)
            {
                log.Error($"Unable to connect to kres on port {port}, ex: {ex}");
            }

            return 0; 
        }

        private static bool SendHeader(NetworkStream stream, IEnumerable<byte> header)
        {
            var headerBytes = header.ToArray();
            stream.Write(headerBytes, 0, headerBytes.Length);

            //log.Debug($"Written header");

            //var response = new byte[1];
            //var bytesRead = stream.Read(response, 0, 1);

            ////log.Debug($"Read header response");
            //if (bytesRead == 1 && response[0] == '1')
            //{
            //    //log.Debug($"Header understood");

                return true;
            //}
            //else
            //{
            //    log.Debug($"Header not understood");
            //}

            return false;
        }

        private static void SendBuffers(NetworkStream stream, IEnumerable<byte[]> messages)
        {
            
            var response = new byte[1];
            byte[] header = new byte[16];
            foreach (var message in messages)
            {
                Array.Copy(BitConverter.GetBytes(message.LongLength), 0, header, 0, sizeof(UInt64));            //8 bytes
                Array.Copy(BitConverter.GetBytes(Crc64.Compute(0, message)), 0, header, 8, sizeof(UInt64));            //8 bytes

                stream.Write(header, 0, header.Length);
                //log.Debug($"Written {header.Length} header size, message {message.LongLength} bytes");

                //log.Debug($"Write message.");
                stream.Write(message, 0, message.Length);
                //log.Debug($"Message written.");

                //var bytesRead = stream.Read(response, 0, 1);
                ////log.Debug($"Read response");
                //if (bytesRead == 1 && response[0] == '1')
                //{
                //    //log.Debug($"Message was sent successfully.");
                //}
                //else
                //{
                //    throw new Exception("unable to write to nework stream");
                //}
            }
        }

        private void ThreadProc()
        {
            log.Info("Starting KresUpdater thread.");

            while (true)
            {
                try
                {
                    log.Info("KresUpdater loop.");

                    if (!CacheLiveStorage.CoreCache.Updated)
                    {
                        log.Info("Cache has was not yet been loaded.");
                        waitHandle.WaitOne(5000, true);
                        continue;
                    }

                    var itemsToRemove = CacheLiveStorage.UdpCache.Where(kvp => (kvp.Value).Created.AddDays(1) < DateTime.UtcNow);
                    log.Info($"Removing old items in idenity cache {itemsToRemove.Count()}.");
                    Models.CacheIPRange value;
                    foreach (var item in itemsToRemove)
                        CacheLiveStorage.UdpCache.TryRemove(item.Key, out value);

                    FreeCaches();

                    if (!updateSmallCaches)
                        UpdateDomains();

                    UpdateIPRanges();

                    if (!updateSmallCaches)
                        UpdatePolicies();

                    UpdateCustomLists();

                    SwapCaches();

                    log.Info("KresUpdate caches set.");
                    updateSmallCaches = false;

                    updatedHandle.Set();

                    log.Info("KresUpdate waiting on update interval.");
                    if (waitHandle.WaitOne(Configuration.GetKresUpdateInterval(), true))
                    {
                        log.Info("KresUpdate reloading on request.");
                    }
                    else
                    {
                        log.Info("KresUpdate reloading on timeout.");
                    }
                }
                catch (Exception ex)
                {
                    tKresLoop = null;
                    log.Error($"{ex}");
                }
            }
        }

        internal static void UpdateSmallCaches()
        {
            updateSmallCaches = true;
        }

        public static void UpdateNow()
        {
            updatedHandle.Reset();
            waitHandle.Set();

            if (updatedHandle.WaitOne(30000, true))
            {
                log.Debug("Kresman updated caches ");
            }
            else
            {
                log.Debug("Kresman did not update caches in time");
            }
        }

        private void UpdateDomains()
        {
            if (CacheLiveStorage.CoreCache.Domains == null)
            {
                log.Debug("No domains to update");
                return;
            }

            var domains = CacheLiveStorage.CoreCache.Domains.OrderBy(t => t.Crc64).ToArray();
            var count = domains.Count();

            log.Debug($"Updating {count} crc domains.");
            byte[] cacheDomainsCrc = new byte[(count * sizeof(UInt64))];
            byte[] cacheAccuracy = new byte[(count * sizeof(UInt16))];
            byte[] cacheFlags = new byte[(count * sizeof(UInt64))];

            for (var i = 0; i < count; i++)
            {
                var flags = domains[i].Flags.SelectMany(BitConverter.GetBytes).ToArray();

                //if (domains[i].Crc64 == 8554644589776997716)
                //{
                //    log.Debug($"Domain {i} CRC {domains[i].Crc64}");
                //}

                //log.Debug($"Array copy crc");
                Array.Copy(BitConverter.GetBytes(domains[i].Crc64), 0, cacheDomainsCrc, i * sizeof(UInt64), sizeof(UInt64));
                //log.Debug($"Array copy accuracy");
                Array.Copy(BitConverter.GetBytes(domains[i].Accuracy), 0, cacheAccuracy, i * sizeof(UInt16), sizeof(UInt16));
                //log.Debug($"Array copy flags");
                for (var j = 0; j < 8; j++) 
                {
                    Array.Copy(new[] { flags[j * 4] }, 0, cacheFlags, i * sizeof(UInt64) + j, 1);
                }
            }

            listener.pushDomainCrcBuffer(null, new List<byte[]>() { cacheDomainsCrc });
            listener.pushDomainAccuracyBuffer(null, new List<byte[]>() { cacheAccuracy });
            listener.pushDomainFlagsBuffer(null, new List<byte[]>() { cacheFlags });
        }

        private void UpdateIPRanges()
        {
            var ipRange = CacheLiveStorage.UdpCache.Select(t => t.Value).ToArray();
            Models.CacheIPRange[] ipRangeCore = null;

            if (CacheLiveStorage.CoreCache.IPRanges != null)
            {
                ipRangeCore = CacheLiveStorage.CoreCache.IPRanges.ToArray();
                ipRange = ipRange.Concat(ipRangeCore).ToArray();
            }

            var count = ipRange.Count();
            if (count == 0)
            {
                log.Info("No ranges to update");
                return;
            }

            log.Debug($"Updating {count} ip ranges.");
            var cacheIPFrom = new List<byte[]>(count);
            var cacheIPTo = new List<byte[]>(count);
            var cacheIdentity = new List<byte[]>(count);
            var cachePolicy = new byte [count * sizeof(UInt32)];
            for (var i = 0; i < count; i++)
            {
                var IPFrom = new byte[sizeof(UInt32) + sizeof(UInt32) + 16 /* sizeof(Int128)*/ ];
                var IPTo = new byte[sizeof(UInt32) + sizeof(UInt32) + 16 /* sizeof(Int128)*/ ];

                //#define AF_INET		2
                //#define AF_INET6	    10

                if (ipRange[i].IpFrom.Hi != 0)
                {
                    Array.Copy(BitConverter.GetBytes(10), 0, IPFrom, 0, sizeof(UInt32));
                    Array.Copy(BitConverter.GetBytes((uint)ipRange[i].IpFrom.Hi), 0, IPFrom, sizeof(UInt32), sizeof(UInt32));
                    Array.Copy(BitConverter.GetBytes(ipRange[i].IpFrom.Hi), 0, IPFrom, sizeof(UInt32) + sizeof(UInt32), sizeof(UInt64));
                    Array.Copy(BitConverter.GetBytes(ipRange[i].IpFrom.Low), 0, IPFrom, sizeof(UInt32) + sizeof(UInt32) + sizeof(UInt64), sizeof(UInt64));
                }
                else
                {
                    Array.Copy(BitConverter.GetBytes(2), 0, IPFrom, 0, sizeof(UInt32));
                    Array.Copy(BitConverter.GetBytes((uint)ipRange[i].IpFrom.Low), 0, IPFrom, sizeof(UInt32), sizeof(UInt32));
                    Array.Copy(BitConverter.GetBytes(ipRange[i].IpFrom.Hi), 0, IPFrom, sizeof(UInt32) + sizeof(UInt32), sizeof(UInt64));
                    Array.Copy(BitConverter.GetBytes(ipRange[i].IpFrom.Low), 0, IPFrom, sizeof(UInt32) + sizeof(UInt32) + sizeof(UInt64), sizeof(UInt64));
                }
                cacheIPFrom.Add(IPFrom);
                
                if (ipRange[i].IpTo.Hi != 0)
                {
                    Array.Copy(BitConverter.GetBytes(10), 0, IPTo, 0, sizeof(UInt32));
                    Array.Copy(BitConverter.GetBytes((uint)ipRange[i].IpTo.Hi), 0, IPTo, sizeof(UInt32), sizeof(UInt32));
                    Array.Copy(BitConverter.GetBytes(ipRange[i].IpTo.Hi), 0, IPTo, sizeof(UInt32) + sizeof(UInt32), sizeof(UInt64));
                    Array.Copy(BitConverter.GetBytes(ipRange[i].IpTo.Low), 0, IPTo, sizeof(UInt32) + sizeof(UInt32) + sizeof(UInt64), sizeof(UInt64));
                }
                else
                {
                    Array.Copy(BitConverter.GetBytes(2), 0, IPTo, 0, sizeof(UInt32));
                    Array.Copy(BitConverter.GetBytes((uint)ipRange[i].IpTo.Low), 0, IPTo, sizeof(UInt32), sizeof(UInt32));
                    Array.Copy(BitConverter.GetBytes(ipRange[i].IpTo.Hi), 0, IPTo, sizeof(UInt32) + sizeof(UInt32), sizeof(UInt64));
                    Array.Copy(BitConverter.GetBytes(ipRange[i].IpTo.Low), 0, IPTo, sizeof(UInt32) + sizeof(UInt32) + sizeof(UInt64), sizeof(UInt64));
                }
                cacheIPTo.Add(IPTo);


                if (ipRange[i].Identity != null)
                {
                    var Identity = new byte[ipRange[i].Identity.Length];
                    Array.Copy(ASCIIEncoding.ASCII.GetBytes(ipRange[i].Identity), 0, Identity, 0, ipRange[i].Identity.Length);
                    cacheIdentity.Add(Identity);
                }
                else
                {
                    var Identity = new byte[1];
                    Array.Copy(ASCIIEncoding.ASCII.GetBytes("\0"), 0, Identity, 0, 1);
                    cacheIdentity.Add(Identity);
                }

                Array.Copy(BitConverter.GetBytes(ipRange[i].PolicyId), 0, cachePolicy, i * (sizeof(UInt32)), sizeof(UInt32));
            }

            listener.pushIPRangeFromBuffer(null, cacheIPFrom);
            listener.pushIPRangeToBuffer(null, cacheIPTo);
            listener.pushIPRangeIdentityBuffer(null, cacheIdentity);
            listener.pushIPRangePolicyBuffer(null, new List<byte[]>() { cachePolicy });
        }

        private void UpdatePolicies()
        {
            if (CacheLiveStorage.CoreCache.Policies == null)
            {
                log.Debug("No policies to update");
                return;
            }

            var policies = CacheLiveStorage.CoreCache.Policies.ToArray();
            var count = policies.Count();

            log.Debug($"Updating {count} policies.");
            var cachePolicyId = new byte[(count * sizeof(UInt32))];
            var cachePolicyStrategy = new byte[(count * sizeof(UInt32))];
            var cachePolicyAudit = new byte[(count * sizeof(UInt32))];
            var cachePolicyBlock = new byte[(count * sizeof(UInt32))];

            for (var i = 0; i < count; i++)
            {
                Array.Copy(BitConverter.GetBytes(policies[i].Policy_id), 0, cachePolicyId, i * sizeof(UInt32), sizeof(UInt32));
                Array.Copy(BitConverter.GetBytes(policies[i].Strategy), 0, cachePolicyStrategy, i * sizeof(UInt32), sizeof(UInt32));
                Array.Copy(BitConverter.GetBytes(policies[i].Audit), 0, cachePolicyAudit, i * sizeof(UInt32), sizeof(UInt32));
                Array.Copy(BitConverter.GetBytes(policies[i].Block), 0, cachePolicyBlock, i * sizeof(UInt32), sizeof(UInt32));
            }

            listener.pushPolicyIDBuffer(null, new List<byte[]>() { cachePolicyId });
            listener.pushPolicyStrategyBuffer(null, new List<byte[]>() { cachePolicyStrategy });
            listener.pushPolicyAuditBuffer(null, new List<byte[]>() { cachePolicyAudit });
            listener.pushPolicyBlockBuffer(null, new List<byte[]>() { cachePolicyBlock });
        }

        private void UpdateCustomLists()
        {
            if (CacheLiveStorage.CoreCache.CustomLists == null)
            {
                log.Debug("No custom list to update");
                return;
            }

            var customlist = CacheLiveStorage.CoreCache.CustomLists.ToArray();
            var count = customlist.Count();

            log.Debug($"Updating {count} custom lists.");
            for (var i = 0; i < count; i++)
            {
                var cacheIdentity = new byte[customlist[i].Identity.Length];
                var cachecustomlist_policyid = new byte[sizeof(Int32)];
                Array.Copy(ASCIIEncoding.ASCII.GetBytes(customlist[i].Identity), 0, cacheIdentity, 0, customlist[i].Identity.Length);

                var cachecustomlist_whitelist = new byte[(customlist[i].WhiteList.Count() * sizeof(UInt64))];
                var wlarray = customlist[i].WhiteList.ToArray();
                for (var j = 0; j < customlist[i].WhiteList.Count(); j++)
                {
                    var crc = Crc64.Compute(0, ASCIIEncoding.ASCII.GetBytes(wlarray[j]));
                    Array.Copy(BitConverter.GetBytes(crc), 0, cachecustomlist_whitelist, j * sizeof(UInt64), sizeof(UInt64));
                }

                var cachecustomlist_blacklist = new byte[(customlist[i].BlackList.Count() * sizeof(UInt64))];
                var blarray = customlist[i].BlackList.ToArray();
                for (var j = 0; j < customlist[i].BlackList.Count(); j++)
                {
                    var crc = Crc64.Compute(0, ASCIIEncoding.ASCII.GetBytes(blarray[j]));
                    Array.Copy(BitConverter.GetBytes(crc), 0, cachecustomlist_blacklist, j * sizeof(UInt64), sizeof(UInt64));
                }

                Array.Copy(BitConverter.GetBytes(customlist[i].PolicyId), 0, cachecustomlist_policyid, 0, sizeof(Int32));

                listener.pushCustomListIdentityBuffer(null, new List<byte[]>() { cacheIdentity });
                listener.pushCustomListWhitelistBuffer(null, new List<byte[]>() { cachecustomlist_whitelist });
                listener.pushCustomListBlacklistBuffer(null, new List<byte[]>() { cachecustomlist_blacklist });
                listener.pushCustomListPolicyIdBuffer(null, new List<byte[]>() { cachecustomlist_policyid });
            }
        }

        private void SwapCaches()
        {
            listener.pushSwapCaches(null, new List<byte[]>());
        }

        private void FreeCaches()
        {
            listener.pushFreeCaches(null, new List<byte[]>());
        }

        internal void Start(Listener listener)
        {
            this.listener = listener;
            tKresLoop = new Thread(ThreadProc);
            tKresLoop.Start();
        }
    }
}
