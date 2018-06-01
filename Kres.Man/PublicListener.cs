using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Threading;
using System.Text;

using Newtonsoft.Json;

namespace Kres.Man
{
    internal class PublicListener
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private Thread tLoop;

        [Flags]
        public enum KresFlags
        {
            flags_none = 0x0,
            flags_accuracy = 1,
            flags_blacklist = 2,
            flags_whitelist = 4,
            flags_drop = 8,
            flags_audit = 16,
        }

        private string GenerateContent(HttpListenerContext ctx, string page)
        {
            var filename = $"Web/{page}";
            if (!System.IO.File.Exists(filename))
            {
                return $"file {filename} does not exist";
            }

            using (var file = File.OpenRead(filename))
            {
                using (var reader = new StreamReader(file))
                {
                    var url = ctx.Request.Url;
                    var encodedUrl = Base64Encode(url.ToString());
                    var ipaddress = ctx.Request.RemoteEndPoint.Address.ToString();
                    var content = reader.ReadToEnd();

                    content = content.Replace("{$targetUrl}", $"{url.Host} from {ipaddress}");
                    content = content.Replace("{$url}", $"{url.ToString()}");
                    content = content.Replace("{$authToken}", $"BFLMPSVZ");
                    content = content.Replace("{$ipToBypass}", ipaddress);
                    content = content.Replace("{$domainToWhitelist}", url.Host);
                    content = content.Replace("{$redirectUrl}", encodedUrl);

                    return content;
                }
            }
        }

        [PublicMapping("passthrough")]
        public object PassThrough(HttpListenerContext ctx, string postdata)
        {
            var list = ctx.Request.Url.Host.Split('.');

            if (!string.IsNullOrEmpty(postdata))
                list = postdata.Split('.');

            for (var i = 0; i < list.Length - 1; i++)
            {
                var joined = string.Join('.', list, i, list.Length - i);
                var bytes = Encoding.ASCII.GetBytes(joined);
                var crc = Crc64.Compute(0, bytes);
                var domain = CacheLiveStorage.CoreCache.Domains.Where(t => t.Crc64 == crc).FirstOrDefault();
                if (domain == null)
                    continue;

                var ipaddress = ctx.Request.RemoteEndPoint.Address;
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

                var ipRange = CacheLiveStorage.UdpCache.Select(t => t.Value).ToArray();
                Models.CacheIPRange[] ipRangeCore = null;
                if (CacheLiveStorage.CoreCache.IPRanges != null)
                {
                    ipRangeCore = CacheLiveStorage.CoreCache.IPRanges.ToArray();
                    ipRange = ipRange.Concat(ipRangeCore).ToArray();
                }

                var range = ipRange.Where(t => t.BintFrom >= ip && ip <= t.BintTo).FirstOrDefault();
                var range_identity = string.Empty;
                var range_policyid = 0;
                if (range != null)
                {
                    range_identity = range.Identity;
                    range_policyid = range.PolicyId;
                }

                Models.PublicListenerConfig views;
                using (var sr = new StreamReader("publiclistenerconfig.json"))
                {
                    views = JsonConvert.DeserializeObject<Models.PublicListenerConfig>(sr.ReadToEnd());
                }

                foreach (var network in views.views)
                {
                    foreach (var cidr in network.networks)
                    {
                        IPNetwork n = IPNetwork.Parse(cidr.ToString());
                        if (!n.Contains(ipaddress))
                            continue;

                        if (!string.IsNullOrEmpty(range_identity))
                        {
                            var custom = CacheLiveStorage.CoreCache.CustomLists.Where(t => string.Compare(t.Identity, range_identity, StringComparison.OrdinalIgnoreCase) == 0).FirstOrDefault();
                            if (custom != null)
                            {
                                if (custom.BlackList.Contains(joined))
                                {
                                    return GenerateContent(ctx, network.blacklist.First());
                                }
                                else if (custom.WhiteList.Contains(joined))
                                {
                                    //allow
                                    return "allow";
                                }
                            }
                        }

                        var policy = CacheLiveStorage.CoreCache.Policies.Where(t => t.Policy_id == range_policyid).FirstOrDefault();
                        if (policy == null)
                        {
                            //no policy
                            return "no policy";
                        }
                        else
                        {
                            var flags = domain.Flags.ToArray()[policy.Policy_id];

                            if ((flags & (int)KresFlags.flags_accuracy) == (int)KresFlags.flags_accuracy)
                            {
                                if (policy.Block > 0 && domain.Accuracy > policy.Block)
                                {
                                    return GenerateContent(ctx, network.accuracy.First());
                                }
                                else
                                {
                                    if (policy.Audit > 0 && domain.Accuracy > policy.Audit)
                                    {
                                        //audit
                                        return "audit";
                                    }
                                    else
                                    {
                                        //no accuracy action
                                        return "no accuracy action";
                                    }
                                }
                            }
                            if ((flags & (int)KresFlags.flags_blacklist) == (int)KresFlags.flags_blacklist)
                            {
                                //block
                                return GenerateContent(ctx, network.legal.First());
                            }
                            if ((flags & (int)KresFlags.flags_whitelist) == (int)KresFlags.flags_whitelist)
                            {
                                //allow whitelist
                                return "allow whitelist";
                            }
                        }
                    }
                }
            }

            return "no-action";
        }
   

        [PublicMapping("bypass")]
        public object Bypass(HttpListenerContext ctx, string postdata, string clientIpAddress, string domainToWhitelist, string authToken, string base64encodedUrlToRedirectTo)
        {
            string identity = clientIpAddress.GetHashCode().ToString("X");

            IPAddress ip;
            if (!IPAddress.TryParse(clientIpAddress, out ip))
            {
                return new Exception($"unable to parse ip address {clientIpAddress}.");
            }

            //TODO: check ipv6 reverse
            var bytes = ip.GetAddressBytes().Reverse().ToArray();
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
                return new Exception($"unable to parse ip address {clientIpAddress}.");
            }

            List<Models.CacheIPRange> ipranges;
            List<Models.CacheCustomList> customlists;
            if (CacheLiveStorage.CoreCache.IPRanges != null)
            {
                ipranges = CacheLiveStorage.CoreCache.IPRanges.ToList();
            }
            else
            {
                ipranges = new List<Models.CacheIPRange>();
            }

            if (CacheLiveStorage.CoreCache.IPRanges != null)
            {
                customlists = CacheLiveStorage.CoreCache.CustomLists.ToList();
            }
            else
            {
                customlists = new List<Models.CacheCustomList>();
            }

           
            ipranges.Add(new Models.CacheIPRange()
            {
                Identity = identity,
                Proto_IpFrom = Encoding.ASCII.GetBytes(intip.ToString()),
                Proto_IpTo = Encoding.ASCII.GetBytes(intip.ToString()),
                PolicyId = 0
            });
            var item = customlists.FirstOrDefault(t => string.Compare(t.Identity, identity, StringComparison.OrdinalIgnoreCase) == 0);
            if (item == null)
            {
                item = new Models.CacheCustomList()
                {
                    Identity = identity,
                    WhiteList = new List<string>() { domainToWhitelist },
                    BlackList = new List<string>(),
                    PolicyId = 0
                };
                log.Info($"Identity {identity} now has {domainToWhitelist} whitelisted.");
            }
            else
            {
                if (!item.WhiteList.Contains(domainToWhitelist))
                {
                    var list = item.WhiteList.ToList();
                    list.Add(domainToWhitelist);
                    item.WhiteList = list;
                    log.Info($"Identity {identity} now has {domainToWhitelist} whitelisted.");
                }
                else
                {
                    log.Info($"Identity {identity} has {domainToWhitelist} already whitelisted.");
                }
            }
            customlists.RemoveAll(t => string.Compare(t.Identity, identity, StringComparison.OrdinalIgnoreCase) == 0);
            customlists.Add(item);

            CacheLiveStorage.CoreCache.IPRanges = ipranges;
            CacheLiveStorage.CoreCache.CustomLists = customlists;

            log.Info($"Updating kres modules.");
            KresUpdater.UpdateSmallCaches();
            KresUpdater.UpdateNow();
            log.Info($"Kres modules have been updated.");

            //var redirectUrl = Base64Decode(base64encodedUrlToRedirectTo);
            //ctx.Response.RedirectLocation = redirectUrl;
            ctx.Response.StatusCode = 418;

            return null;
        }

        private static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = Convert.FromBase64String(base64EncodedData);
            return Encoding.UTF8.GetString(base64EncodedBytes);
        }

        private static string Base64Encode(string data)
        {
            var bytes = Encoding.UTF8.GetBytes(data);
            return Convert.ToBase64String(bytes);
        }


        private void ThreadProc()
        {
            log.Info("Starting PublicListener thread.");

            try
            {
                while (true)
                {
                    var prefix = Configuration.GetPublicListener();
                    var prefixs = Configuration.GetPublicListenerS();
                    log.Info($"Starting PublicListener listener {prefix}.");
                    var listener = new HttpListener();

                    listener.Prefixes.Add(prefix);
                    listener.Start();
                    while (true)
                    {
                        //log.Info($"Waiting for listener context.");
                        HttpListenerContext ctx = listener.GetContext();

                        ThreadPool.QueueUserWorkItem((_) =>
                        {
                            try
                            {
                                log.Info($"RemoteEndPoint = {ctx.Request.RemoteEndPoint.ToString()}");

                                string methodName = ctx.Request.Url.Segments[1].Replace("/", "");
                                string[] strParams = ctx.Request.Url
                                                        .Segments
                                                        .Skip(2)
                                                        .Select(s => s.Replace("/", ""))
                                                        .ToArray();

                                MethodInfo method = null;

                                method = this.GetType()
                                                    .GetMethods()
                                                    .Where(mi => mi.GetCustomAttributes(true).Any(attr => attr is PublicMapping && ((PublicMapping)attr).Map == methodName))
                                                    .First();

                                var args = method.GetParameters().Skip(2).Select((p, i) => Convert.ChangeType(strParams[i], p.ParameterType));
                                var @params = new object[args.Count() + 2];

                                var inLength = ctx.Request.ContentLength64;
                                //log.Info($"Content len = {inLength}.");

                                var inBuffer = new byte[4096];
                                var buffer = new byte[inLength];
                                int totalBytesRead = 0;
                                int bytesRead = 0;
                                while (true)
                                {
                                    bytesRead = ctx.Request.InputStream.Read(inBuffer, 0, inBuffer.Length);
                                    if (bytesRead == 0 || bytesRead == -1)
                                    {
                                        //log.Info($"Nothing to read len = {totalBytesRead}.");
                                        break;
                                    }

                                    Array.Copy(inBuffer, 0, buffer, totalBytesRead, bytesRead);
                                    totalBytesRead += bytesRead;

                                    if (totalBytesRead == inLength)
                                    {
                                        //log.Info($"Read finished to read len = {totalBytesRead}.");
                                        break;
                                    }
                                }

                                @params[0] = ctx;
                                @params[1] = Encoding.UTF8.GetString(buffer);
                                Array.Copy(args.ToArray(), 0, @params, 2, args.Count());

                                log.Info($"Invoking {method.Name}");
                                try
                                {
                                    var ret = method.Invoke(this, @params) as string;

                                    if (ret != null)
                                    {
                                        var outBuffer = Encoding.UTF8.GetBytes(ret);
                                        ctx.Response.ContentLength64 = outBuffer.LongLength;
                                        ctx.Response.OutputStream.Write(outBuffer, 0, outBuffer.Length);
                                    }

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
                                // log.Error($"{ex}");

                                try
                                {
                                    var ret = PassThrough(ctx, null) as string;

                                    var outBuffer = Encoding.UTF8.GetBytes(ret);
                                    ctx.Response.ContentLength64 = outBuffer.LongLength;
                                    ctx.Response.OutputStream.Write(outBuffer, 0, outBuffer.Length);
                                    ctx.Response.OutputStream.Close();
                                }
                                catch (Exception ex2)
                                {
                                    log.Error($"{ex2}");
                                }
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
