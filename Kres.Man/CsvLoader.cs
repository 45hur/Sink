using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Kres.Man
{

    internal class CsvLoader
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(typeof(CsvLoader));

        public static Models.Cache LoadCacheFromCsv()
        {
            var result = new Models.Cache()
            {
                CustomLists = LoadCustomLists(),
                Domains = LoadDomains(),
                IPRanges = LoadIPRanges(),
                Policies = LoadPolicies(),
            };

            return result;
        }

        private static List<Models.CacheCustomList> LoadCustomLists()
        {
            var result = new List<Models.CacheCustomList>();
            var csv = new CsvHelper.CsvReader(File.OpenText("custom.csv"));

            while (csv.Read())
            {
                var item = new Models.CacheCustomList
                {
                    Identity = csv.GetField(0),
                    WhiteList = csv.GetField(1).Split(';'),
                    BlackList = csv.GetField(2).Split(';')
                };

                result.Add(item);
            }

            return result;
        }

        private static List<Models.CacheDomain> LoadDomains()
        {
            var result = new List<Models.CacheDomain>();
            var csv = new CsvHelper.CsvReader(File.OpenText("domains.csv"));
            
            while (csv.Read())
            {
                var item = new Models.CacheDomain
                {
                    Crc64 = Crc64.Compute(0, ASCIIEncoding.ASCII.GetBytes(csv.GetField(0))),
                    Accuracy = Convert.ToInt32(csv.GetField(1)),
                    Flags = BitConverter.GetBytes(Convert.ToUInt64(csv.GetField(2)))
                };
                result.Add(item);
            }

            return result;
        }

        private static List<Models.CacheIPRange> LoadIPRanges()
        {
            var result = new List<Models.CacheIPRange>();
            var csv = new CsvHelper.CsvReader(File.OpenText("ranges.csv"));

            while (csv.Read())
            {
                var item = new Models.CacheIPRange
                {
                    IpFrom = new Models.Int128(),
                    IpTo = new Models.Int128(),
                    Identity = csv.GetField(2),
                    PolicyId = Convert.ToInt32(csv.GetField(3))
                };
                result.Add(item);
            }

            return result;
        }

        private static List<Models.CachePolicy> LoadPolicies()
        {
            var result = new List<Models.CachePolicy>();
            var csv = new CsvHelper.CsvReader(File.OpenText("policy.csv"));

            while (csv.Read())
            {
                var item = new Models.CachePolicy
                {
                    Policy_id = Convert.ToInt32(csv.GetField(0)),
                    Strategy = Convert.ToInt32(csv.GetField(1)),
                    Audit = Convert.ToInt32(csv.GetField(2)),
                    Block = Convert.ToInt32(csv.GetField(3)),
                };
                result.Add(item);
            }

            return result;
        }
    }
}
