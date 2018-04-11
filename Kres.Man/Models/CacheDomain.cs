using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using ProtoBuf;

namespace Kres.Man.Models
{
    [ProtoContract]
    public class CacheDomain
    {
        [ProtoMember(1)]
        public IEnumerable<byte> Proto_Crc64 { get; set; }

        [ProtoMember(2)]
        public int Accuracy { get; set; }

        [ProtoMember(3)]
        public IEnumerable<int> Flags { get; set; }

        public UInt64 Crc64
        {
            get
            {
                //return Convert.ToUInt64(Proto_Crc64.SelectMany(BitConverter.GetBytes).ToArray());
                var text = Encoding.ASCII.GetString(Proto_Crc64.ToArray());
                return Convert.ToUInt64(text);
            }
            set
            {
                //Proto_Crc64 = new[] { 0 }; 
                Proto_Crc64 = BitConverter.GetBytes(value);
            }
        }
    }
}
