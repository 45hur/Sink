using System;

using ProtoBuf;

namespace Kres.Man.Models
{
    [ProtoContract]
    public class Int128
    {
        [ProtoMember(1)]
        public UInt64 Low { get; set; }

        [ProtoMember(2)]
        public UInt64 Hi { get; set; }

        public static Kres.Man.Models.Int128 Convert(BigMath.Int128 param)
        {
            var result = new Kres.Man.Models.Int128();
            result.Hi = param.High;
            result.Low = param.Low;

            return result;
        }
    }
}
