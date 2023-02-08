using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CryptoUtils.CryptoNote;
using NBitcoin;
using static CryptoUtils.HexExtensions;

namespace CryptoUtils
{
  class ScalarKey
  {
    public static byte[] GenerateKeyDerivation(Key prP, Key prS)
    {
     return CryptonoteUtils.GenerateKeyDerivation(prP.ToBytes(), prS.ToBytes());
    }
    public static byte[] DerivePublicKey(byte[] derivation, byte[] key, int index)
    {
      return CryptonoteUtils.DerivePublicKey(derivation.ToHex(), index, key.ToHex()).HexToByteArray();
    }

  }

}
