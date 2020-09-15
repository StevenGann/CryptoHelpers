using System;
using System.Collections.Generic;
using System.Text;

namespace CryptoHelpers
{
    public class Blockchain<T> where T : class, IBinarySerializable
    {
    }

    public interface IBinarySerializable
    {
        byte[] Serialize();

        void Deserialize(byte[] bytes);
    }
}