using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Net;
using System.Reflection;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using Newtonsoft.Json;

namespace Kres.Man
{
    public class Startup
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

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
        
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.Run(async (context) =>
            {
                if (string.Compare(context.Request.Path, "/passthrough", StringComparison.InvariantCultureIgnoreCase) == 0)
                {
                    string postdata;
                    using (var reader = new StreamReader(context.Request.Body))
                    {
                        postdata = reader.ReadToEnd();
                    }

                    await context.Response.WriteAsync(PassThrough(context, postdata));
                }
                else
                if (context.Request.Path.ToString().StartsWith("/bypass"))
                {
                    var split = context.Request.Path.ToString().Split('/');
                    if (split.Length != 6)
                        return;

                    Bypass(context, split[2], split[3], split[4], split[5]);
                    
                    context.Response.StatusCode = 418;
                }
                else
                {
                    await context.Response.WriteAsync(PassThrough(context, string.Empty));
                }
            });
        }

        private string GenerateContent(HttpContext ctx, string page)
        {
            if (page.Contains(".."))
                return string.Empty;

            var filename = $"Web/{page}";
            if (!File.Exists(filename))
            {
                return GenerateContent(ctx, "/blacklist.en.html");
            }

            using (var file = File.OpenRead(filename))
            {
                using (var reader = new StreamReader(file))
                {
                    var protocol = (ctx.Request.IsHttps)
                        ? "https"
                        : "http";
                    var host = ctx.Request.Host.ToString();
                    var request = ctx.Request.Path.ToString();
                    var port = ctx.Connection.LocalPort;

                    var url = $"{protocol}://{host}:{port}{request}";

                    var encodedUrl = Base64Encode(url);
                    var ipaddress = ctx.Connection.RemoteIpAddress;
                    var content = reader.ReadToEnd();

                    content = content.Replace("{$targetUrl}", $"{url}");
                    content = content.Replace("{$url}", $"{request}");
                    content = content.Replace("{$authToken}", $"BFLMPSVZ");
                    content = content.Replace("{$ipToBypass}", ipaddress.ToString());
                    content = content.Replace("{$domainToWhitelist}", host);
                    content = content.Replace("{$redirectUrl}", encodedUrl);
                    content = content.Replace("{$companyName}", "O2");
                    content = content.Replace("{$email}", "support@o2.cz");
                    content = content.Replace("{$phone}", "+420 800 02 02 02");
                    content = content.Replace("{$website}", "2018 - Whalebone");


                    return content;
                }
            }
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

        public string PassThrough(HttpContext ctx, string postdata)
        {
            var list = ctx.Request.Host.ToString().Split('.');

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

                var ipaddress = ctx.Connection.RemoteIpAddress;
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
                                    //return "allow";
                                    return GenerateContent(ctx, network.blacklist.First());
                                }
                            }
                        }

                        var policy = CacheLiveStorage.CoreCache.Policies.Where(t => t.Policy_id == range_policyid).FirstOrDefault();
                        if (policy == null)
                        {
                            //no policy
                            //return "no policy";
                            return GenerateContent(ctx, network.blacklist.First());
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
                                        //return "audit";
                                        return GenerateContent(ctx, network.blacklist.First());
                                    }
                                    else
                                    {
                                        //no accuracy action
                                        //return "no accuracy action";
                                        return GenerateContent(ctx, network.blacklist.First());
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
                                //return "allow whitelist";
                                return GenerateContent(ctx, network.blacklist.First());
                            }
                        }
                    }
                }
            }

            //return "no-action";
            return "";
        }


        public string Bypass(HttpContext ctx, string clientIpAddress, string domainToWhitelist, string authToken, string base64encodedUrlToRedirectTo)
        {
            log.Info($"Bypass request, ip={clientIpAddress}, {domainToWhitelist}.");

            if (string.Compare(authToken, "BFLMPSVZ", StringComparison.OrdinalIgnoreCase) != 0)
            {
                return "";
            }

            string identity = clientIpAddress.GetHashCode().ToString("X");

            IPAddress ip;
            if (!IPAddress.TryParse(clientIpAddress, out ip))
            {
                return new Exception($"unable to parse ip address {clientIpAddress}.").Message;
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
                return new Exception($"unable to parse ip address {clientIpAddress}.").Message;
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
            

            return null;
        }
    }
}
