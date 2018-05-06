using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using ProtoBuf;

namespace Kres.Man.Models
{
    [ProtoContract]
    public class CacheIPRange
    {
        [ProtoMember(1)]
        public IEnumerable<byte> Proto_IpFrom { get; set; }

        [ProtoMember(2)]
        public IEnumerable<byte> Proto_IpTo { get; set; }

        [ProtoMember(3)]
        public string Identity { get; set; }

        [ProtoMember(4)]
        public Int32 PolicyId { get; set; }

        public DateTime Created { get; set; }

        public Int128 IpFrom
        {
            get
            {
                //return Convert.ToUInt64(Proto_Crc64.SelectMany(BitConverter.GetBytes).ToArray());
                var text = Encoding.ASCII.GetString(Proto_IpFrom.ToArray());
                text = text.TrimStart('0');
                var int128 = BigMath.Int128.Parse(text);
                return Int128.Convert(int128);
            }
            set { Proto_IpFrom = new byte[] { 0 }; }
        }
        public Int128 IpTo
        {
            get
            {
                //return Convert.ToUInt64(Proto_Crc64.SelectMany(BitConverter.GetBytes).ToArray());
                var text = Encoding.ASCII.GetString(Proto_IpTo.ToArray());
                text = text.TrimStart('0');
                var int128 = BigMath.Int128.Parse(text);
                return Int128.Convert(int128);
            }
            set { Proto_IpFrom = new byte[] { 0 }; }
        }

        public string Text
        {
            get { return Encoding.ASCII.GetString(Proto_IpTo.ToArray()).TrimStart('0'); }
        }
        public string ParsedText
        {
            get { return BigMath.Int128.Parse(Encoding.ASCII.GetString(Proto_IpTo.ToArray()).TrimStart('0')).ToString(); }
        }
    }
}
