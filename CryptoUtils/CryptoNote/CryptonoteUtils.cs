using System;
using System.Linq;
using System.Numerics;
using System.Text.RegularExpressions;

namespace CryptoUtils.CryptoNote
{

  //https://github.com/monero-project/monero/blob/36241552b56b156c08319935baf7afda12deb3c5/src/crypto/crypto_ops_builder/crypto-ops-old.c

  public static class CryptonoteUtils
  {

    public static readonly Int32[] FeMa2 = { -12721188, -3529, 0, 0, 0, 0, 0, 0, 0, 0 };
    public static readonly Int32[] FeMa = { -486662, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    public static readonly Int32[] FeFffb1 = { -31702527, -2466483, -26106795, -12203692, -12169197, -321052, 14850977, -10296299, -16929438, -407568 };
    public static readonly Int32[] fe_sqrtm1 = { -32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482 };
    public static readonly Int32[] fe_fffb2 = { 8166131, -6741800, -17040804, 3154616, 21461005, 1466302, -30876704, -6368709, 10503587, -13363080 };
    public static readonly Int32[] fe_fffb3 = { -13620103, 14639558, 4532995, 7679154, 16815101, -15883539, -22863840, -14813421, 13716513, -6477756 };
    public static readonly Int32[] fe_fffb4 = { -21786234, -12173074, 21573800, 4524538, -4645904, 16204591, 8012863, -8444712, 3212926, 6885324 };
    public static readonly Int32[] FeD2 = { -21827239, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968, 9444199 };
    public static readonly Int32[] FeD = { -10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116 };
    public const string H = "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94";
    public const string I = "0100000000000000000000000000000000000000000000000000000000000000";
    public const string Z = "0000000000000000000000000000000000000000000000000000000000000000";

    public enum STRUCT_SIZES
    {
      GE_P3 = 160,
      GE_P2 = 120,
      GE_P1P1 = 160,
      GE_CACHED = 160,
      EC_SCALAR = 32,
      EC_POINT = 32,
      KEY_IMAGE = 32,
      GE_DSMP = 160 * 8,
      SIGNATURE = 64
    };

    public static byte[] GenerateKeyDerivation(byte[] pub, byte[] sec)
    {
      if (pub.Length != 32 || sec.Length != 32)
      {
        throw new Exception("Invalid input length");
      }

      var P = NaclFastCn.GeScalarmult(pub, sec);
      return NaclFastCn.GeScalarmult(P, HexToByteArray(D2s(8))); //mul8 to ensure group
    }

    public static string DerivePublicKey(string derivation, Int32 outIndex, string pub)
    {
      if (derivation.Length != 64 || pub.Length != 64)
      {
        throw new Exception("Invalid input length!");
      }

      string s = DerivationToScalar(derivation, outIndex);
      return ByteArrayToHex(NaclFastCn.GeAdd(HexToByteArray(pub), NaclFastCn.GeScalarmultBase(HexToByteArray(s))));
    }

    public static string DecryptAmount(string ViewKey, string TxPubKey, Int32 outIndex, string encMask)
    {
      byte[] tmp = GenerateKeyDerivation(HexToByteArray(TxPubKey), HexToByteArray(ViewKey));
      string recvDerivation = ByteArrayToHex(tmp);

      if (recvDerivation == null || recvDerivation == "")
        throw new Exception("Failed to generate amount");

      string mask = "";
      if (encMask != null && encMask != "")
      {
        mask = ScSub(encMask, HashToScalar(DerivationToScalar(recvDerivation, outIndex)));
      }
      else
      {
        mask = I;
      }

      return mask;
    }
    public static string GetAmount(string amount, byte[] derivation, int index)
    {
      var scalar1 = CryptonoteUtils.DerivationToScalar(derivation.ToHex(), 1);
      var hash = EcdhAmountHash(scalar1.HexToByteArray());

      var decAmount = HexXor8(amount.HexToByteArray(), hash);
      return H2d(decAmount.HexToByteArray()).ToString();
    }

    static byte[] EcdhAmountHash(byte[] key)
    {
      byte[] data = new byte[38];
      Buffer.BlockCopy(System.Text.Encoding.UTF8.GetBytes("amount"), 0, data, 0, 6);
      Buffer.BlockCopy(key, 0, data, 6, key.Length);
      return CryptonoteUtils.CnFastHash(data);
    }

    static string HexXor8(byte[] amount, byte[] key)
    {
      for (Int32 i = 0; i < 8; i++)
      {
        amount[i] ^= key[i];
      }

      return amount.ToHex();
    }
    static UInt64 H2d(byte[] key)
    {
      UInt64 vali = 0;
      int j = 0;
      for (j = 7; j >= 0; j--)
      {
        vali = vali * 256 + ((uint)key[j]);
      }

      return vali;
    }
    public static string Sk2Rct(string scalar1)
    {
      byte[] second = HexToByteArray(HashToScalar(scalar1));
      return ByteArrayToHex(second);
    }
    public static string DecodeRctEcdh(string ecdhMask, string Sk2Rct)
    {

      var amountRes = ScSub(ecdhMask, Sk2Rct);
      return amountRes;
    }
    private static UInt64 Load4(byte[] ba)
    {
      UInt64 result = 0;
      result = (UInt64)ba[0];
      result |= ((UInt64)ba[1]) << 8;
      result |= ((UInt64)ba[2]) << 16;
      result |= ((UInt64)ba[3]) << 24;
      return result;
    }

    private static UInt64 Load3(byte[] ba)
    {
      UInt64 result = 0;
      result = (UInt64)ba[0];
      result |= ((UInt64)ba[1]) << 8;
      result |= ((UInt64)ba[2]) << 16;
      return result;
    }

    private static void Pack64(Int64 src, byte[] dst, int from)
    {
      byte[] srcBytes = BitConverter.GetBytes(src);

      Array.Copy(srcBytes, 0, dst, from, sizeof(Int64));
    }

    public static byte[] CnFastHash(byte[] input)
    {
      Sha3 sha3 = new Sha3();
      return sha3.Kessak(input);
    }

    public static byte[] ScReduce32(byte[] seed)
    {
      const int kRange = 4;

      Int64 s0 = (Int64)(0x1FFFFF & Load3(seed.SubArray(0, kRange)));
      Int64 s1 = (Int64)(0x1FFFFF & (Load4(seed.SubArray(2, kRange)) >> 5));
      Int64 s2 = (Int64)(0x1FFFFF & (Load3(seed.SubArray(5, kRange)) >> 2));
      Int64 s3 = (Int64)(0x1FFFFF & (Load4(seed.SubArray(7, kRange)) >> 7));
      Int64 s4 = (Int64)(0x1FFFFF & (Load4(seed.SubArray(10, kRange)) >> 4));
      Int64 s5 = (Int64)(0x1FFFFF & (Load3(seed.SubArray(13, kRange)) >> 1));
      Int64 s6 = (Int64)(0x1FFFFF & (Load4(seed.SubArray(15, kRange)) >> 6));
      Int64 s7 = (Int64)(0x1FFFFF & (Load3(seed.SubArray(18, kRange)) >> 3));
      Int64 s8 = (Int64)(0x1FFFFF & Load3(seed.SubArray(21, kRange)));
      Int64 s9 = (Int64)(0x1FFFFF & (Load4(seed.SubArray(23, kRange)) >> 5));
      Int64 s10 = (Int64)(0x1FFFFF & (Load3(seed.SubArray(26, kRange)) >> 2));
      Int64 s11 = (Int64)(Load4(seed.SubArray(28, kRange)) >> 7);
      Int64 s12 = 0;

      Int64 carry0;
      Int64 carry1;
      Int64 carry2;
      Int64 carry3;
      Int64 carry4;
      Int64 carry5;
      Int64 carry6;
      Int64 carry7;
      Int64 carry8;
      Int64 carry9;
      Int64 carry10;
      Int64 carry11;

      carry0 = (s0 + (1 << 20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
      carry2 = (s2 + (1 << 20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
      carry4 = (s4 + (1 << 20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
      carry6 = (s6 + (1 << 20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
      carry8 = (s8 + (1 << 20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
      carry10 = (s10 + (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21;

      carry1 = (s1 + (1 << 20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
      carry3 = (s3 + (1 << 20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
      carry5 = (s5 + (1 << 20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
      carry7 = (s7 + (1 << 20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
      carry9 = (s9 + (1 << 20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
      carry11 = (s11 + (1 << 20)) >> 21; s12 += carry11; s11 -= carry11 << 21;

      //banch of magic values
      s0 += s12 * 666643;
      s1 += s12 * 470296;
      s2 += s12 * 654183;
      s3 -= s12 * 997805;
      s4 += s12 * 136657;
      s5 -= s12 * 683901;
      s12 = 0;

      carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
      carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
      carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
      carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
      carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
      carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
      carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
      carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
      carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
      carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
      carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;
      carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 << 21;

      s0 += s12 * 666643;
      s1 += s12 * 470296;
      s2 += s12 * 654183;
      s3 -= s12 * 997805;
      s4 += s12 * 136657;
      s5 -= s12 * 683901;

      carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
      carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
      carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
      carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
      carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
      carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
      carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
      carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
      carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
      carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
      carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;

      byte[] reducedSeed = new byte[32 + sizeof(Int64)];

      Pack64(s0, reducedSeed, 0);
      Pack64(s0 >> 8, reducedSeed, 1);
      Pack64((s0 >> 16) | (s1 << 5), reducedSeed, 2);
      Pack64(s1 >> 3, reducedSeed, 3);
      Pack64(s1 >> 11, reducedSeed, 4);
      Pack64((s1 >> 19) | (s2 << 2), reducedSeed, 5);
      Pack64(s2 >> 6, reducedSeed, 6);
      Pack64((s2 >> 14) | (s3 << 7), reducedSeed, 7);
      Pack64(s3 >> 1, reducedSeed, 8);
      Pack64(s3 >> 9, reducedSeed, 9);
      Pack64((s3 >> 17) | (s4 << 4), reducedSeed, 10);
      Pack64(s4 >> 4, reducedSeed, 11);
      Pack64(s4 >> 12, reducedSeed, 12);
      Pack64((s4 >> 20) | (s5 << 1), reducedSeed, 13);
      Pack64(s5 >> 7, reducedSeed, 14);
      Pack64((s5 >> 15) | (s6 << 6), reducedSeed, 15);
      Pack64(s6 >> 2, reducedSeed, 16);
      Pack64(s6 >> 10, reducedSeed, 17);
      Pack64((s6 >> 18) | (s7 << 3), reducedSeed, 18);
      Pack64(s7 >> 5, reducedSeed, 19);
      Pack64(s7 >> 13, reducedSeed, 20);
      Pack64(s8 >> 0, reducedSeed, 21);
      Pack64(s8 >> 8, reducedSeed, 22);
      Pack64((s8 >> 16) | (s9 << 5), reducedSeed, 23);
      Pack64(s9 >> 3, reducedSeed, 24);
      Pack64(s9 >> 11, reducedSeed, 25);
      Pack64((s9 >> 19) | (s10 << 2), reducedSeed, 26);
      Pack64(s10 >> 6, reducedSeed, 27);
      Pack64((s10 >> 14) | (s11 << 7), reducedSeed, 28);
      Pack64(s11 >> 1, reducedSeed, 29);
      Pack64(s11 >> 9, reducedSeed, 30);
      Pack64(s11 >> 17, reducedSeed, 31);

      return reducedSeed.SubArray(0, 32);
    }

    public static String ByteArrayToHex(byte[] ba)
    {
      string hex = BitConverter.ToString(ba);
      var res = hex.Replace("-", "");
      return res;
    }

    public static byte[] HexToByteArray(String hex)
    {
      if (!IsValidHex(hex))
      {
        throw new Exception("Invalid hex");
      }

      int NumberChars = hex.Length;
      byte[] bytes = new byte[NumberChars / 2];
      for (int i = 0; i < NumberChars; i += 2)
        bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
      return bytes;
    }

    public static string HexXor(string hex1, string hex2)
    {
      if (hex1 == null || hex2 == null || hex1.Length != hex2.Length || hex1.Length % 2 != 0 || hex2.Length % 2 != 0)
      {
        throw new Exception("Hex string(s) is/are invalid!");
      }
      byte[] bin1 = HexToByteArray(hex1);
      byte[] bin2 = HexToByteArray(hex2);
      byte[] xor = new byte[bin1.Length];
      for (Int32 i = 0; i < xor.Length; i++)
      {
        xor[i] = (byte)(bin1[i] ^ bin2[i]);
      }
      return ByteArrayToHex(xor);

    }

    public static string DerivationToScalar(string derivation, Int64 outputIndex)
    {
      string buf = "";
      if (derivation.Length != ((Int64)STRUCT_SIZES.EC_POINT * 2))
      {
        throw new Exception("Invalid derivation length!");
      }
      buf += derivation;
      string enc = EncodeVarint(outputIndex);
      if (enc.Length > 10 * 2)
      {
        throw new Exception("output_index didn't fit in 64-bit varint");
      }
      buf += enc;
      return HashToScalar(buf);
    }
    public static string DerivationToScalar(string derivation, string enc)
    {
      string buf = "";
      if (derivation.Length != ((Int64)STRUCT_SIZES.EC_POINT * 2))
      {
        throw new Exception("Invalid derivation length!");
      }
      buf += derivation;

      if (enc.Length > 10 * 2)
      {
        throw new Exception("output_index didn't fit in 64-bit varint");
      }
      buf += enc;
      return HashToScalar(buf);
    }
    public static string[] AbsToRelOffsets(string[] offsets)
    {
      if (offsets.Length == 0)
      {
        return offsets;
      }
      for (var i = offsets.Length - 1; i >= 1; --i)
      {
        BigInteger a = new BigInteger(Int64.Parse(offsets[i - 1]));
        BigInteger b = new BigInteger(Int64.Parse(offsets[i]));

        offsets[i] = BigInteger.Subtract(b, a).ToString();
      }
      return offsets;
    }

    public static string D2s(Int64 v)
    {
      return SwapEndian(D2h(v));
    }

    public static string D2s(string v)
    {
      return SwapEndian(D2h(v));
    }

    public static string D2h(Int64 v)
    {
      if (v.ToString().Length > 15)
      {
        throw new Exception("integer should be entered as a string for precision");
      }

      string padding = "";

      for (Int64 i = 0; i < 63; i++)
      {
        padding += "0";
      }

      BigInteger vBig = new BigInteger(v);
      string tmp = padding + vBig.ToString("x"); //to lower case
      return tmp.Substring(tmp.Length - 64, 64);
    }

    public static string SwapEndian(string hex)
    {
      if (hex.Length % 2 != 0)
      {
        throw new Exception("length must be a multiple of 2!");
      }

      var data = "";
      for (var i = 1; i <= hex.Length / 2; i++)
      {
        data += hex.Substring(hex.Length - 2 * i, 2);
      }

      return data;
    }

    public static string D2h(string v)
    {
      if (v.ToString().Length > 15)
      {
        throw new Exception("integer should be entered as a string for precision");
      }

      string padding = "";

      for (Int64 i = 0; i < 63; i++)
      {
        padding += "0";
      }

      BigInteger.TryParse(v, out BigInteger vBig);
      string tmp = padding + vBig.ToString("x"); //to lower case
      return tmp.Substring(tmp.Length - 64, 64);
    }

    public static bool IsValidHex(string hex)
    {
      if (hex == "" || hex == null)
      {
        return false;
      }

      var exp = new Regex("[0-9a-fA-F]{" + hex.Length + "}");
      return exp.IsMatch(hex);
    }

    public static string ZeroCommit(string amount)
    {
      if (!IsValidHex(amount) || amount.Length != 64)
      {
        throw new Exception("invalid amount!");
      }

      byte[] C = NaclFastCn.GeDoubleScalarmultBaseVartime(
          HexToByteArray(amount),
          HexToByteArray(H),
          HexToByteArray(I)
      );
      return ByteArrayToHex(C);
    }

    public static string EncodeVarint(Int64 i)
    {
      BigInteger iBig = new BigInteger(i);
      string res = "";
      string tmp = "";

      // While i >= b10000000
      while (iBig.CompareTo(0x80) >= 0)
      {
        // out.append i & b01111111 | b10000000
        tmp = ("0" + ((iBig.ToByteArray()[0] & 0x7f) | 0x80).ToString("x"));
        res += tmp.Substring(tmp.Length - 2, 2);
        iBig = BigInteger.Divide(iBig, new BigInteger(128));
      }
      tmp = "0" + iBig.ToString("x");
      res += tmp.Substring(tmp.Length - 2, 2);
      return res;
    }

    public static string EncodeVarint(BigInteger iBig)
    {

      string res = "";
      string tmp = "";

      // While i >= b10000000
      while (iBig.CompareTo(0x80) >= 0)
      {
        // out.append i & b01111111 | b10000000
        tmp = ("0" + ((iBig.ToByteArray()[0] & 0x7f) | 0x80).ToString("x"));
        res += tmp.Substring(tmp.Length - 2, 2);
        iBig = BigInteger.Divide(iBig, new BigInteger(128));
      }
      tmp = "0" + iBig.ToString("x");
      res += tmp.Substring(tmp.Length - 2, 2);

      if (res.Length > 10 * 2)
      {
        throw new Exception("output_index didn't fit in 64-bit varint");
      }

      return res;
    }
    public static string HashToScalar(string buf)
    {
      byte[] hash = CnFastHash(HexToByteArray(buf));
      byte[] scalar = ScReduce32(hash);
      return ByteArrayToHex(scalar);
    }

    public static string ScSub(string scalar1, string scalar2)
    {
      byte[] res = new byte[32];
      ScSub(ref res, HexToByteArray(scalar1), HexToByteArray(scalar2));
      return ByteArrayToHex(res);
    }
    public static void ScSub(ref byte[] s, byte[] a, byte[] b)
    {
      Int64 a0 = (Int64)(2097151 & Load3(a));
      Int64 a1 = (Int64)(2097151 & (Load4(a.SubArray(2)) >> 5));
      Int64 a2 = (Int64)(2097151 & (Load3(a.SubArray(5)) >> 2));
      Int64 a3 = (Int64)(2097151 & (Load4(a.SubArray(7)) >> 7));
      Int64 a4 = (Int64)(2097151 & (Load4(a.SubArray(10)) >> 4));
      Int64 a5 = (Int64)(2097151 & (Load3(a.SubArray(13)) >> 1));
      Int64 a6 = (Int64)(2097151 & (Load4(a.SubArray(15)) >> 6));
      Int64 a7 = (Int64)(2097151 & (Load3(a.SubArray(18)) >> 3));
      Int64 a8 = (Int64)(2097151 & Load3(a.SubArray(21)));
      Int64 a9 = (Int64)(2097151 & (Load4(a.SubArray(23)) >> 5));
      Int64 a10 = (Int64)(2097151 & (Load3(a.SubArray(26)) >> 2));
      Int64 a11 = (Int64)((Load4(a.SubArray(28)) >> 7));
      Int64 b0 = (Int64)(2097151 & Load3(b));
      Int64 b1 = (Int64)(2097151 & (Load4(b.SubArray(2)) >> 5));
      Int64 b2 = (Int64)(2097151 & (Load3(b.SubArray(5)) >> 2));
      Int64 b3 = (Int64)(2097151 & (Load4(b.SubArray(7)) >> 7));
      Int64 b4 = (Int64)(2097151 & (Load4(b.SubArray(10)) >> 4));
      Int64 b5 = (Int64)(2097151 & (Load3(b.SubArray(13)) >> 1));
      Int64 b6 = (Int64)(2097151 & (Load4(b.SubArray(15)) >> 6));
      Int64 b7 = (Int64)(2097151 & (Load3(b.SubArray(18)) >> 3));
      Int64 b8 = (Int64)(2097151 & Load3(b.SubArray(21)));
      Int64 b9 = (Int64)(2097151 & (Load4(b.SubArray(23)) >> 5));
      Int64 b10 = (Int64)(2097151 & (Load3(b.SubArray(26)) >> 2));
      Int64 b11 = (Int64)((Load4(b.SubArray(28)) >> 7));
      Int64 s0 = a0 - b0;
      Int64 s1 = a1 - b1;
      Int64 s2 = a2 - b2;
      Int64 s3 = a3 - b3;
      Int64 s4 = a4 - b4;
      Int64 s5 = a5 - b5;
      Int64 s6 = a6 - b6;
      Int64 s7 = a7 - b7;
      Int64 s8 = a8 - b8;
      Int64 s9 = a9 - b9;
      Int64 s10 = a10 - b10;
      Int64 s11 = a11 - b11;
      Int64 s12 = 0;
      Int64 carry0;
      Int64 carry1;
      Int64 carry2;
      Int64 carry3;
      Int64 carry4;
      Int64 carry5;
      Int64 carry6;
      Int64 carry7;
      Int64 carry8;
      Int64 carry9;
      Int64 carry10;
      Int64 carry11;

      carry0 = (s0 + (1 << 20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
      carry2 = (s2 + (1 << 20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
      carry4 = (s4 + (1 << 20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
      carry6 = (s6 + (1 << 20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
      carry8 = (s8 + (1 << 20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
      carry10 = (s10 + (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21;

      carry1 = (s1 + (1 << 20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
      carry3 = (s3 + (1 << 20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
      carry5 = (s5 + (1 << 20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
      carry7 = (s7 + (1 << 20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
      carry9 = (s9 + (1 << 20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
      carry11 = (s11 + (1 << 20)) >> 21; s12 += carry11; s11 -= carry11 << 21;

      s0 += s12 * 666643;
      s1 += s12 * 470296;
      s2 += s12 * 654183;
      s3 -= s12 * 997805;
      s4 += s12 * 136657;
      s5 -= s12 * 683901;
      s12 = 0;

      carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
      carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
      carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
      carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
      carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
      carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
      carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
      carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
      carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
      carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
      carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;
      carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 << 21;

      s0 += s12 * 666643;
      s1 += s12 * 470296;
      s2 += s12 * 654183;
      s3 -= s12 * 997805;
      s4 += s12 * 136657;
      s5 -= s12 * 683901;

      carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
      carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
      carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
      carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
      carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
      carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
      carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
      carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
      carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
      carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
      carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;

      s[0] = (byte)((s0 >> 0));
      s[1] = (byte)(s0 >> 8);
      s[2] = (byte)((s0 >> 16) | (s1 << 5));
      s[3] = (byte)(s1 >> 3);
      s[4] = (byte)(s1 >> 11);
      s[5] = (byte)((s1 >> 19) | (s2 << 2));
      s[6] = (byte)(s2 >> 6);
      s[7] = (byte)((s2 >> 14) | (s3 << 7));
      s[8] = (byte)(s3 >> 1);
      s[9] = (byte)(s3 >> 9);
      s[10] = (byte)((s3 >> 17) | (s4 << 4));
      s[11] = (byte)(s4 >> 4);
      s[12] = (byte)(s4 >> 12);
      s[13] = (byte)((s4 >> 20) | (s5 << 1));
      s[14] = (byte)(s5 >> 7);
      s[15] = (byte)((s5 >> 15) | (s6 << 6));
      s[16] = (byte)(s6 >> 2);
      s[17] = (byte)(s6 >> 10);
      s[18] = (byte)((s6 >> 18) | (s7 << 3));
      s[19] = (byte)(s7 >> 5);
      s[20] = (byte)(s7 >> 13);
      s[21] = (byte)(s8 >> 0);
      s[22] = (byte)(s8 >> 8);
      s[23] = (byte)((s8 >> 16) | (s9 << 5));
      s[24] = (byte)(s9 >> 3);
      s[25] = (byte)(s9 >> 11);
      s[26] = (byte)((s9 >> 19) | (s10 << 2));
      s[27] = (byte)(s10 >> 6);
      s[28] = (byte)((s10 >> 14) | (s11 << 7));
      s[29] = (byte)(s11 >> 1);
      s[30] = (byte)(s11 >> 9);
      s[31] = (byte)(s11 >> 17);
    }


    public static void ScMulsub(ref byte[] s, byte[] a, byte[] b, byte[] c)
    {
      Int64 a0 = 2097151 & (Int64)Load3(a);
      Int64 a1 = 2097151 & (Int64)(Load4(a.SubArray(2)) >> 5);
      Int64 a2 = 2097151 & (Int64)(Load3(a.SubArray(5)) >> 2);
      Int64 a3 = 2097151 & (Int64)(Load4(a.SubArray(7)) >> 7);
      Int64 a4 = 2097151 & (Int64)(Load4(a.SubArray(10)) >> 4);
      Int64 a5 = 2097151 & (Int64)(Load3(a.SubArray(13)) >> 1);
      Int64 a6 = 2097151 & (Int64)(Load4(a.SubArray(15)) >> 6);
      Int64 a7 = 2097151 & (Int64)(Load3(a.SubArray(18)) >> 3);
      Int64 a8 = 2097151 & (Int64)Load3(a.SubArray(21));
      Int64 a9 = 2097151 & (Int64)(Load4(a.SubArray(23)) >> 5);
      Int64 a10 = 2097151 & (Int64)(Load3(a.SubArray(26)) >> 2);
      Int64 a11 = (Int64)(Load4(a.SubArray(28)) >> 7);
      Int64 b0 = 2097151 & (Int64)Load3(b);
      Int64 b1 = 2097151 & (Int64)(Load4(b.SubArray(2)) >> 5);
      Int64 b2 = 2097151 & (Int64)(Load3(b.SubArray(5)) >> 2);
      Int64 b3 = 2097151 & (Int64)(Load4(b.SubArray(7)) >> 7);
      Int64 b4 = 2097151 & (Int64)(Load4(b.SubArray(10)) >> 4);
      Int64 b5 = 2097151 & (Int64)(Load3(b.SubArray(13)) >> 1);
      Int64 b6 = 2097151 & (Int64)(Load4(b.SubArray(15)) >> 6);
      Int64 b7 = 2097151 & (Int64)(Load3(b.SubArray(18)) >> 3);
      Int64 b8 = 2097151 & (Int64)Load3(b.SubArray(21));
      Int64 b9 = 2097151 & (Int64)(Load4(b.SubArray(23)) >> 5);
      Int64 b10 = 2097151 & (Int64)(Load3(b.SubArray(26)) >> 2);
      Int64 b11 = (Int64)(Load4(b.SubArray(28)) >> 7);
      Int64 c0 = 2097151 & (Int64)Load3(c);
      Int64 c1 = 2097151 & (Int64)(Load4(c.SubArray(2)) >> 5);
      Int64 c2 = 2097151 & (Int64)(Load3(c.SubArray(5)) >> 2);
      Int64 c3 = 2097151 & (Int64)(Load4(c.SubArray(7)) >> 7);
      Int64 c4 = 2097151 & (Int64)(Load4(c.SubArray(10)) >> 4);
      Int64 c5 = 2097151 & (Int64)(Load3(c.SubArray(13)) >> 1);
      Int64 c6 = 2097151 & (Int64)(Load4(c.SubArray(15)) >> 6);
      Int64 c7 = 2097151 & (Int64)(Load3(c.SubArray(18)) >> 3);
      Int64 c8 = 2097151 & (Int64)Load3(c.SubArray(21));
      Int64 c9 = 2097151 & (Int64)(Load4(c.SubArray(23)) >> 5);
      Int64 c10 = 2097151 & (Int64)(Load3(c.SubArray(26)) >> 2);
      Int64 c11 = (Int64)(Load4(c.SubArray(28)) >> 7);
      Int64 s0;
      Int64 s1;
      Int64 s2;
      Int64 s3;
      Int64 s4;
      Int64 s5;
      Int64 s6;
      Int64 s7;
      Int64 s8;
      Int64 s9;
      Int64 s10;
      Int64 s11;
      Int64 s12;
      Int64 s13;
      Int64 s14;
      Int64 s15;
      Int64 s16;
      Int64 s17;
      Int64 s18;
      Int64 s19;
      Int64 s20;
      Int64 s21;
      Int64 s22;
      Int64 s23;
      Int64 carry0;
      Int64 carry1;
      Int64 carry2;
      Int64 carry3;
      Int64 carry4;
      Int64 carry5;
      Int64 carry6;
      Int64 carry7;
      Int64 carry8;
      Int64 carry9;
      Int64 carry10;
      Int64 carry11;
      Int64 carry12;
      Int64 carry13;
      Int64 carry14;
      Int64 carry15;
      Int64 carry16;
      Int64 carry17;
      Int64 carry18;
      Int64 carry19;
      Int64 carry20;
      Int64 carry21;
      Int64 carry22;

      s0 = c0 - a0 * b0;
      s1 = c1 - (a0 * b1 + a1 * b0);
      s2 = c2 - (a0 * b2 + a1 * b1 + a2 * b0);
      s3 = c3 - (a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0);
      s4 = c4 - (a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0);
      s5 = c5 - (a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0);
      s6 = c6 - (a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0);
      s7 = c7 - (a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0);
      s8 = c8 - (a0 * b8 + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1 + a8 * b0);
      s9 = c9 - (a0 * b9 + a1 * b8 + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3 + a7 * b2 + a8 * b1 + a9 * b0);
      s10 = c10 - (a0 * b10 + a1 * b9 + a2 * b8 + a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4 + a7 * b3 + a8 * b2 + a9 * b1 + a10 * b0);
      s11 = c11 - (a0 * b11 + a1 * b10 + a2 * b9 + a3 * b8 + a4 * b7 + a5 * b6 + a6 * b5 + a7 * b4 + a8 * b3 + a9 * b2 + a10 * b1 + a11 * b0);
      s12 = -(a1 * b11 + a2 * b10 + a3 * b9 + a4 * b8 + a5 * b7 + a6 * b6 + a7 * b5 + a8 * b4 + a9 * b3 + a10 * b2 + a11 * b1);
      s13 = -(a2 * b11 + a3 * b10 + a4 * b9 + a5 * b8 + a6 * b7 + a7 * b6 + a8 * b5 + a9 * b4 + a10 * b3 + a11 * b2);
      s14 = -(a3 * b11 + a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5 + a10 * b4 + a11 * b3);
      s15 = -(a4 * b11 + a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6 + a10 * b5 + a11 * b4);
      s16 = -(a5 * b11 + a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7 + a10 * b6 + a11 * b5);
      s17 = -(a6 * b11 + a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7 + a11 * b6);
      s18 = -(a7 * b11 + a8 * b10 + a9 * b9 + a10 * b8 + a11 * b7);
      s19 = -(a8 * b11 + a9 * b10 + a10 * b9 + a11 * b8);
      s20 = -(a9 * b11 + a10 * b10 + a11 * b9);
      s21 = -(a10 * b11 + a11 * b10);
      s22 = -a11 * b11;
      s23 = 0;

      carry0 = (s0 + (1 << 20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
      carry2 = (s2 + (1 << 20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
      carry4 = (s4 + (1 << 20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
      carry6 = (s6 + (1 << 20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
      carry8 = (s8 + (1 << 20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
      carry10 = (s10 + (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
      carry12 = (s12 + (1 << 20)) >> 21; s13 += carry12; s12 -= carry12 << 21;
      carry14 = (s14 + (1 << 20)) >> 21; s15 += carry14; s14 -= carry14 << 21;
      carry16 = (s16 + (1 << 20)) >> 21; s17 += carry16; s16 -= carry16 << 21;
      carry18 = (s18 + (1 << 20)) >> 21; s19 += carry18; s18 -= carry18 << 21;
      carry20 = (s20 + (1 << 20)) >> 21; s21 += carry20; s20 -= carry20 << 21;
      carry22 = (s22 + (1 << 20)) >> 21; s23 += carry22; s22 -= carry22 << 21;

      carry1 = (s1 + (1 << 20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
      carry3 = (s3 + (1 << 20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
      carry5 = (s5 + (1 << 20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
      carry7 = (s7 + (1 << 20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
      carry9 = (s9 + (1 << 20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
      carry11 = (s11 + (1 << 20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
      carry13 = (s13 + (1 << 20)) >> 21; s14 += carry13; s13 -= carry13 << 21;
      carry15 = (s15 + (1 << 20)) >> 21; s16 += carry15; s15 -= carry15 << 21;
      carry17 = (s17 + (1 << 20)) >> 21; s18 += carry17; s17 -= carry17 << 21;
      carry19 = (s19 + (1 << 20)) >> 21; s20 += carry19; s19 -= carry19 << 21;
      carry21 = (s21 + (1 << 20)) >> 21; s22 += carry21; s21 -= carry21 << 21;

      s11 += s23 * 666643;
      s12 += s23 * 470296;
      s13 += s23 * 654183;
      s14 -= s23 * 997805;
      s15 += s23 * 136657;
      s16 -= s23 * 683901;

      s10 += s22 * 666643;
      s11 += s22 * 470296;
      s12 += s22 * 654183;
      s13 -= s22 * 997805;
      s14 += s22 * 136657;
      s15 -= s22 * 683901;

      s9 += s21 * 666643;
      s10 += s21 * 470296;
      s11 += s21 * 654183;
      s12 -= s21 * 997805;
      s13 += s21 * 136657;
      s14 -= s21 * 683901;

      s8 += s20 * 666643;
      s9 += s20 * 470296;
      s10 += s20 * 654183;
      s11 -= s20 * 997805;
      s12 += s20 * 136657;
      s13 -= s20 * 683901;

      s7 += s19 * 666643;
      s8 += s19 * 470296;
      s9 += s19 * 654183;
      s10 -= s19 * 997805;
      s11 += s19 * 136657;
      s12 -= s19 * 683901;

      s6 += s18 * 666643;
      s7 += s18 * 470296;
      s8 += s18 * 654183;
      s9 -= s18 * 997805;
      s10 += s18 * 136657;
      s11 -= s18 * 683901;

      carry6 = (s6 + (1 << 20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
      carry8 = (s8 + (1 << 20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
      carry10 = (s10 + (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
      carry12 = (s12 + (1 << 20)) >> 21; s13 += carry12; s12 -= carry12 << 21;
      carry14 = (s14 + (1 << 20)) >> 21; s15 += carry14; s14 -= carry14 << 21;
      carry16 = (s16 + (1 << 20)) >> 21; s17 += carry16; s16 -= carry16 << 21;

      carry7 = (s7 + (1 << 20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
      carry9 = (s9 + (1 << 20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
      carry11 = (s11 + (1 << 20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
      carry13 = (s13 + (1 << 20)) >> 21; s14 += carry13; s13 -= carry13 << 21;
      carry15 = (s15 + (1 << 20)) >> 21; s16 += carry15; s15 -= carry15 << 21;

      s5 += s17 * 666643;
      s6 += s17 * 470296;
      s7 += s17 * 654183;
      s8 -= s17 * 997805;
      s9 += s17 * 136657;
      s10 -= s17 * 683901;

      s4 += s16 * 666643;
      s5 += s16 * 470296;
      s6 += s16 * 654183;
      s7 -= s16 * 997805;
      s8 += s16 * 136657;
      s9 -= s16 * 683901;

      s3 += s15 * 666643;
      s4 += s15 * 470296;
      s5 += s15 * 654183;
      s6 -= s15 * 997805;
      s7 += s15 * 136657;
      s8 -= s15 * 683901;

      s2 += s14 * 666643;
      s3 += s14 * 470296;
      s4 += s14 * 654183;
      s5 -= s14 * 997805;
      s6 += s14 * 136657;
      s7 -= s14 * 683901;

      s1 += s13 * 666643;
      s2 += s13 * 470296;
      s3 += s13 * 654183;
      s4 -= s13 * 997805;
      s5 += s13 * 136657;
      s6 -= s13 * 683901;

      s0 += s12 * 666643;
      s1 += s12 * 470296;
      s2 += s12 * 654183;
      s3 -= s12 * 997805;
      s4 += s12 * 136657;
      s5 -= s12 * 683901;
      s12 = 0;

      carry0 = (s0 + (1 << 20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
      carry2 = (s2 + (1 << 20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
      carry4 = (s4 + (1 << 20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
      carry6 = (s6 + (1 << 20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
      carry8 = (s8 + (1 << 20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
      carry10 = (s10 + (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21;

      carry1 = (s1 + (1 << 20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
      carry3 = (s3 + (1 << 20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
      carry5 = (s5 + (1 << 20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
      carry7 = (s7 + (1 << 20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
      carry9 = (s9 + (1 << 20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
      carry11 = (s11 + (1 << 20)) >> 21; s12 += carry11; s11 -= carry11 << 21;

      s0 += s12 * 666643;
      s1 += s12 * 470296;
      s2 += s12 * 654183;
      s3 -= s12 * 997805;
      s4 += s12 * 136657;
      s5 -= s12 * 683901;
      s12 = 0;

      carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
      carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
      carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
      carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
      carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
      carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
      carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
      carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
      carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
      carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
      carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;
      carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 << 21;

      s0 += s12 * 666643;
      s1 += s12 * 470296;
      s2 += s12 * 654183;
      s3 -= s12 * 997805;
      s4 += s12 * 136657;
      s5 -= s12 * 683901;

      carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
      carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
      carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
      carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
      carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
      carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
      carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
      carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
      carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
      carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
      carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;

      s[0] = (byte)(s0 >> 0);
      s[1] = (byte)(s0 >> 8);
      s[2] = (byte)((s0 >> 16) | (s1 << 5));
      s[3] = (byte)(s1 >> 3);
      s[4] = (byte)(s1 >> 11);
      s[5] = (byte)((s1 >> 19) | (s2 << 2));
      s[6] = (byte)(s2 >> 6);
      s[7] = (byte)((s2 >> 14) | (s3 << 7));
      s[8] = (byte)(s3 >> 1);
      s[9] = (byte)(s3 >> 9);
      s[10] = (byte)((s3 >> 17) | (s4 << 4));
      s[11] = (byte)(s4 >> 4);
      s[12] = (byte)(s4 >> 12);
      s[13] = (byte)((s4 >> 20) | (s5 << 1));
      s[14] = (byte)(s5 >> 7);
      s[15] = (byte)((s5 >> 15) | (s6 << 6));
      s[16] = (byte)(s6 >> 2);
      s[17] = (byte)(s6 >> 10);
      s[18] = (byte)((s6 >> 18) | (s7 << 3));
      s[19] = (byte)(s7 >> 5);
      s[20] = (byte)(s7 >> 13);
      s[21] = (byte)(s8 >> 0);
      s[22] = (byte)(s8 >> 8);
      s[23] = (byte)((s8 >> 16) | (s9 << 5));
      s[24] = (byte)(s9 >> 3);
      s[25] = (byte)(s9 >> 11);
      s[26] = (byte)((s9 >> 19) | (s10 << 2));
      s[27] = (byte)(s10 >> 6);
      s[28] = (byte)((s10 >> 14) | (s11 << 7));
      s[29] = (byte)(s11 >> 1);
      s[30] = (byte)(s11 >> 9);
      s[31] = (byte)(s11 >> 17);
    }
    public static void ScAdd(ref byte[] s, byte[] a, byte[] b)
    {
      Int64 a0 = (Int64)(2097151 & Load3(a));
      Int64 a1 = (Int64)(2097151 & (Load4(a.SubArray(2)) >> 5));
      Int64 a2 = (Int64)(2097151 & (Load3(a.SubArray(5)) >> 2));
      Int64 a3 = (Int64)(2097151 & (Load4(a.SubArray(7)) >> 7));
      Int64 a4 = (Int64)(2097151 & (Load4(a.SubArray(10)) >> 4));
      Int64 a5 = (Int64)(2097151 & (Load3(a.SubArray(13)) >> 1));
      Int64 a6 = (Int64)(2097151 & (Load4(a.SubArray(15)) >> 6));
      Int64 a7 = (Int64)(2097151 & (Load3(a.SubArray(18)) >> 3));
      Int64 a8 = (Int64)(2097151 & Load3(a.SubArray(21)));
      Int64 a9 = (Int64)(2097151 & (Load4(a.SubArray(23)) >> 5));
      Int64 a10 = (Int64)(2097151 & (Load3(a.SubArray(26)) >> 2));
      Int64 a11 = (Int64)((Load4(a.SubArray(28)) >> 7));
      Int64 b0 = (Int64)(2097151 & Load3(b));
      Int64 b1 = (Int64)(2097151 & (Load4(b.SubArray(2)) >> 5));
      Int64 b2 = (Int64)(2097151 & (Load3(b.SubArray(5)) >> 2));
      Int64 b3 = (Int64)(2097151 & (Load4(b.SubArray(7)) >> 7));
      Int64 b4 = (Int64)(2097151 & (Load4(b.SubArray(10)) >> 4));
      Int64 b5 = (Int64)(2097151 & (Load3(b.SubArray(13)) >> 1));
      Int64 b6 = (Int64)(2097151 & (Load4(b.SubArray(15)) >> 6));
      Int64 b7 = (Int64)(2097151 & (Load3(b.SubArray(18)) >> 3));
      Int64 b8 = (Int64)(2097151 & Load3(b.SubArray(21)));
      Int64 b9 = (Int64)(2097151 & (Load4(b.SubArray(23)) >> 5));
      Int64 b10 = (Int64)(2097151 & (Load3(b.SubArray(26)) >> 2));
      Int64 b11 = (Int64)((Load4(b.SubArray(28)) >> 7));
      Int64 s0 = a0 + b0;
      Int64 s1 = a1 + b1;
      Int64 s2 = a2 + b2;
      Int64 s3 = a3 + b3;
      Int64 s4 = a4 + b4;
      Int64 s5 = a5 + b5;
      Int64 s6 = a6 + b6;
      Int64 s7 = a7 + b7;
      Int64 s8 = a8 + b8;
      Int64 s9 = a9 + b9;
      Int64 s10 = a10 + b10;
      Int64 s11 = a11 + b11;
      Int64 s12 = 0;
      Int64 carry0;
      Int64 carry1;
      Int64 carry2;
      Int64 carry3;
      Int64 carry4;
      Int64 carry5;
      Int64 carry6;
      Int64 carry7;
      Int64 carry8;
      Int64 carry9;
      Int64 carry10;
      Int64 carry11;

      carry0 = (s0 + (1 << 20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
      carry2 = (s2 + (1 << 20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
      carry4 = (s4 + (1 << 20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
      carry6 = (s6 + (1 << 20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
      carry8 = (s8 + (1 << 20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
      carry10 = (s10 + (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21;

      carry1 = (s1 + (1 << 20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
      carry3 = (s3 + (1 << 20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
      carry5 = (s5 + (1 << 20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
      carry7 = (s7 + (1 << 20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
      carry9 = (s9 + (1 << 20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
      carry11 = (s11 + (1 << 20)) >> 21; s12 += carry11; s11 -= carry11 << 21;

      s0 += s12 * 666643;
      s1 += s12 * 470296;
      s2 += s12 * 654183;
      s3 -= s12 * 997805;
      s4 += s12 * 136657;
      s5 -= s12 * 683901;
      s12 = 0;

      carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
      carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
      carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
      carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
      carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
      carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
      carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
      carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
      carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
      carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
      carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;
      carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 << 21;

      s0 += s12 * 666643;
      s1 += s12 * 470296;
      s2 += s12 * 654183;
      s3 -= s12 * 997805;
      s4 += s12 * 136657;
      s5 -= s12 * 683901;

      carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
      carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
      carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
      carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
      carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
      carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
      carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
      carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
      carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
      carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
      carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;

      s[0] = (byte)(s0 >> 0);
      s[1] = (byte)(s0 >> 8);
      s[2] = (byte)((s0 >> 16) | (s1 << 5));
      s[3] = (byte)(s1 >> 3);
      s[4] = (byte)(s1 >> 11);
      s[5] = (byte)((s1 >> 19) | (s2 << 2));
      s[6] = (byte)(s2 >> 6);
      s[7] = (byte)((s2 >> 14) | (s3 << 7));
      s[8] = (byte)(s3 >> 1);
      s[9] = (byte)(s3 >> 9);
      s[10] = (byte)((s3 >> 17) | (s4 << 4));
      s[11] = (byte)(s4 >> 4);
      s[12] = (byte)(s4 >> 12);
      s[13] = (byte)((s4 >> 20) | (s5 << 1));
      s[14] = (byte)(s5 >> 7);
      s[15] = (byte)((s5 >> 15) | (s6 << 6));
      s[16] = (byte)(s6 >> 2);
      s[17] = (byte)(s6 >> 10);
      s[18] = (byte)((s6 >> 18) | (s7 << 3));
      s[19] = (byte)(s7 >> 5);
      s[20] = (byte)(s7 >> 13);
      s[21] = (byte)(s8 >> 0);
      s[22] = (byte)(s8 >> 8);
      s[23] = (byte)((s8 >> 16) | (s9 << 5));
      s[24] = (byte)(s9 >> 3);
      s[25] = (byte)(s9 >> 11);
      s[26] = (byte)((s9 >> 19) | (s10 << 2));
      s[27] = (byte)(s10 >> 6);
      s[28] = (byte)((s10 >> 14) | (s11 << 7));
      s[29] = (byte)(s11 >> 1);
      s[30] = (byte)(s11 >> 9);
      s[31] = (byte)(s11 >> 17);
    }

    public static string DeriveSecretKey(string derivation, Int32 outIndex, string sec)
    {
      if (derivation.Length != 64 || sec.Length != 64)
      {
        throw new Exception("Invalid input length!");
      }

      byte[] scalar = HexToByteArray(DerivationToScalar(derivation, outIndex));
      byte[] res = new byte[32];
      ScAdd(ref res, scalar, HexToByteArray(sec));
      return ByteArrayToHex(res);
    }

    private static Int64 Signum(Int64 a)
    {
      return (a >> 63) - ((-a) >> 63);
    }

    public static Int64 ScCheck(byte[] s)
    {
      Int64 s0 = (Int64)Load4(s);
      Int64 s1 = (Int64)Load4(s.SubArray(4));
      Int64 s2 = (Int64)Load4(s.SubArray(8));
      Int64 s3 = (Int64)Load4(s.SubArray(12));
      Int64 s4 = (Int64)Load4(s.SubArray(16));
      Int64 s5 = (Int64)Load4(s.SubArray(20));
      Int64 s6 = (Int64)Load4(s.SubArray(24));
      Int64 s7 = (Int64)Load4(s.SubArray(28));
      return (
          (Signum(1559614444 - s0)) +
          (Signum(1477600026 - s1) << 1) +
          (Signum(2734136534 - s2) << 2) +
          (Signum(350157278 - s3) << 3) +
          (Signum(-s4) << 4) +
          (Signum(-s5) << 5) +
          (Signum(-s6) << 6) +
          (Signum(268435456 - s7) << 7)
      ) >> 8;
    }

    public static void FeTobytes(ref byte[] s, Int32[] h)
    {
      Int32 h0 = h[0];
      Int32 h1 = h[1];
      Int32 h2 = h[2];
      Int32 h3 = h[3];
      Int32 h4 = h[4];
      Int32 h5 = h[5];
      Int32 h6 = h[6];
      Int32 h7 = h[7];
      Int32 h8 = h[8];
      Int32 h9 = h[9];
      Int32 q;
      Int32 carry0;
      Int32 carry1;
      Int32 carry2;
      Int32 carry3;
      Int32 carry4;
      Int32 carry5;
      Int32 carry6;
      Int32 carry7;
      Int32 carry8;
      Int32 carry9;

      q = (19 * h9 + (((Int32)1) << 24)) >> 25;
      q = (h0 + q) >> 26;
      q = (h1 + q) >> 25;
      q = (h2 + q) >> 26;
      q = (h3 + q) >> 25;
      q = (h4 + q) >> 26;
      q = (h5 + q) >> 25;
      q = (h6 + q) >> 26;
      q = (h7 + q) >> 25;
      q = (h8 + q) >> 26;
      q = (h9 + q) >> 25;

      /* Goal: Output h-(2^255-19)q, which is between 0 and 2^255-20. */
      h0 += 19 * q;
      /* Goal: Output h-2^255 q, which is between 0 and 2^255-20. */

      carry0 = h0 >> 26; h1 += carry0; h0 -= carry0 << 26;
      carry1 = h1 >> 25; h2 += carry1; h1 -= carry1 << 25;
      carry2 = h2 >> 26; h3 += carry2; h2 -= carry2 << 26;
      carry3 = h3 >> 25; h4 += carry3; h3 -= carry3 << 25;
      carry4 = h4 >> 26; h5 += carry4; h4 -= carry4 << 26;
      carry5 = h5 >> 25; h6 += carry5; h5 -= carry5 << 25;
      carry6 = h6 >> 26; h7 += carry6; h6 -= carry6 << 26;
      carry7 = h7 >> 25; h8 += carry7; h7 -= carry7 << 25;
      carry8 = h8 >> 26; h9 += carry8; h8 -= carry8 << 26;
      carry9 = h9 >> 25; h9 -= carry9 << 25;
      /* h10 = carry9 */

      /*
      Goal: Output h0+...+2^255 h10-2^255 q, which is between 0 and 2^255-20.
      Have h0+...+2^230 h9 between 0 and 2^255-1;
      evidently 2^255 h10-2^255 q = 0.
      Goal: Output h0+...+2^230 h9.
      */

      s[0] = (byte)(h0 >> 0);
      s[1] = (byte)(h0 >> 8);
      s[2] = (byte)(h0 >> 16);
      s[3] = (byte)((h0 >> 24) | (h1 << 2));
      s[4] = (byte)(h1 >> 6);
      s[5] = (byte)(h1 >> 14);
      s[6] = (byte)((h1 >> 22) | (h2 << 3));
      s[7] = (byte)(h2 >> 5);
      s[8] = (byte)(h2 >> 13);
      s[9] = (byte)((h2 >> 21) | (h3 << 5));
      s[10] = (byte)(h3 >> 3);
      s[11] = (byte)(h3 >> 11);
      s[12] = (byte)((h3 >> 19) | (h4 << 6));
      s[13] = (byte)(h4 >> 2);
      s[14] = (byte)(h4 >> 10);
      s[15] = (byte)(h4 >> 18);
      s[16] = (byte)(h5 >> 0);
      s[17] = (byte)(h5 >> 8);
      s[18] = (byte)(h5 >> 16);
      s[19] = (byte)((h5 >> 24) | (h6 << 1));
      s[20] = (byte)(h6 >> 7);
      s[21] = (byte)(h6 >> 15);
      s[22] = (byte)((h6 >> 23) | (h7 << 3));
      s[23] = (byte)(h7 >> 5);
      s[24] = (byte)(h7 >> 13);
      s[25] = (byte)((h7 >> 21) | (h8 << 4));
      s[26] = (byte)(h8 >> 4);
      s[27] = (byte)(h8 >> 12);
      s[28] = (byte)((h8 >> 20) | (h9 << 6));
      s[29] = (byte)(h9 >> 2);
      s[30] = (byte)(h9 >> 10);
      s[31] = (byte)(h9 >> 18);
    }

    public static void FeMul(ref Int32[] h, Int32[] f, Int32[] g)
    {
      Int32 f0 = f[0];
      Int32 f1 = f[1];
      Int32 f2 = f[2];
      Int32 f3 = f[3];
      Int32 f4 = f[4];
      Int32 f5 = f[5];
      Int32 f6 = f[6];
      Int32 f7 = f[7];
      Int32 f8 = f[8];
      Int32 f9 = f[9];
      Int32 g0 = g[0];
      Int32 g1 = g[1];
      Int32 g2 = g[2];
      Int32 g3 = g[3];
      Int32 g4 = g[4];
      Int32 g5 = g[5];
      Int32 g6 = g[6];
      Int32 g7 = g[7];
      Int32 g8 = g[8];
      Int32 g9 = g[9];
      Int32 g1_19 = 19 * g1; /* 1.959375*2^29 */
      Int32 g2_19 = 19 * g2; /* 1.959375*2^30; still ok */
      Int32 g3_19 = 19 * g3;
      Int32 g4_19 = 19 * g4;
      Int32 g5_19 = 19 * g5;
      Int32 g6_19 = 19 * g6;
      Int32 g7_19 = 19 * g7;
      Int32 g8_19 = 19 * g8;
      Int32 g9_19 = 19 * g9;
      Int32 f1_2 = 2 * f1;
      Int32 f3_2 = 2 * f3;
      Int32 f5_2 = 2 * f5;
      Int32 f7_2 = 2 * f7;
      Int32 f9_2 = 2 * f9;
      Int64 f0g0 = f0 * (Int64)g0;
      Int64 f0g1 = f0 * (Int64)g1;
      Int64 f0g2 = f0 * (Int64)g2;
      Int64 f0g3 = f0 * (Int64)g3;
      Int64 f0g4 = f0 * (Int64)g4;
      Int64 f0g5 = f0 * (Int64)g5;
      Int64 f0g6 = f0 * (Int64)g6;
      Int64 f0g7 = f0 * (Int64)g7;
      Int64 f0g8 = f0 * (Int64)g8;
      Int64 f0g9 = f0 * (Int64)g9;
      Int64 f1g0 = f1 * (Int64)g0;
      Int64 f1g1_2 = f1_2 * (Int64)g1;
      Int64 f1g2 = f1 * (Int64)g2;
      Int64 f1g3_2 = f1_2 * (Int64)g3;
      Int64 f1g4 = f1 * (Int64)g4;
      Int64 f1g5_2 = f1_2 * (Int64)g5;
      Int64 f1g6 = f1 * (Int64)g6;
      Int64 f1g7_2 = f1_2 * (Int64)g7;
      Int64 f1g8 = f1 * (Int64)g8;
      Int64 f1g9_38 = f1_2 * (Int64)g9_19;
      Int64 f2g0 = f2 * (Int64)g0;
      Int64 f2g1 = f2 * (Int64)g1;
      Int64 f2g2 = f2 * (Int64)g2;
      Int64 f2g3 = f2 * (Int64)g3;
      Int64 f2g4 = f2 * (Int64)g4;
      Int64 f2g5 = f2 * (Int64)g5;
      Int64 f2g6 = f2 * (Int64)g6;
      Int64 f2g7 = f2 * (Int64)g7;
      Int64 f2g8_19 = f2 * (Int64)g8_19;
      Int64 f2g9_19 = f2 * (Int64)g9_19;
      Int64 f3g0 = f3 * (Int64)g0;
      Int64 f3g1_2 = f3_2 * (Int64)g1;
      Int64 f3g2 = f3 * (Int64)g2;
      Int64 f3g3_2 = f3_2 * (Int64)g3;
      Int64 f3g4 = f3 * (Int64)g4;
      Int64 f3g5_2 = f3_2 * (Int64)g5;
      Int64 f3g6 = f3 * (Int64)g6;
      Int64 f3g7_38 = f3_2 * (Int64)g7_19;
      Int64 f3g8_19 = f3 * (Int64)g8_19;
      Int64 f3g9_38 = f3_2 * (Int64)g9_19;
      Int64 f4g0 = f4 * (Int64)g0;
      Int64 f4g1 = f4 * (Int64)g1;
      Int64 f4g2 = f4 * (Int64)g2;
      Int64 f4g3 = f4 * (Int64)g3;
      Int64 f4g4 = f4 * (Int64)g4;
      Int64 f4g5 = f4 * (Int64)g5;
      Int64 f4g6_19 = f4 * (Int64)g6_19;
      Int64 f4g7_19 = f4 * (Int64)g7_19;
      Int64 f4g8_19 = f4 * (Int64)g8_19;
      Int64 f4g9_19 = f4 * (Int64)g9_19;
      Int64 f5g0 = f5 * (Int64)g0;
      Int64 f5g1_2 = f5_2 * (Int64)g1;
      Int64 f5g2 = f5 * (Int64)g2;
      Int64 f5g3_2 = f5_2 * (Int64)g3;
      Int64 f5g4 = f5 * (Int64)g4;
      Int64 f5g5_38 = f5_2 * (Int64)g5_19;
      Int64 f5g6_19 = f5 * (Int64)g6_19;
      Int64 f5g7_38 = f5_2 * (Int64)g7_19;
      Int64 f5g8_19 = f5 * (Int64)g8_19;
      Int64 f5g9_38 = f5_2 * (Int64)g9_19;
      Int64 f6g0 = f6 * (Int64)g0;
      Int64 f6g1 = f6 * (Int64)g1;
      Int64 f6g2 = f6 * (Int64)g2;
      Int64 f6g3 = f6 * (Int64)g3;
      Int64 f6g4_19 = f6 * (Int64)g4_19;
      Int64 f6g5_19 = f6 * (Int64)g5_19;
      Int64 f6g6_19 = f6 * (Int64)g6_19;
      Int64 f6g7_19 = f6 * (Int64)g7_19;
      Int64 f6g8_19 = f6 * (Int64)g8_19;
      Int64 f6g9_19 = f6 * (Int64)g9_19;
      Int64 f7g0 = f7 * (Int64)g0;
      Int64 f7g1_2 = f7_2 * (Int64)g1;
      Int64 f7g2 = f7 * (Int64)g2;
      Int64 f7g3_38 = f7_2 * (Int64)g3_19;
      Int64 f7g4_19 = f7 * (Int64)g4_19;
      Int64 f7g5_38 = f7_2 * (Int64)g5_19;
      Int64 f7g6_19 = f7 * (Int64)g6_19;
      Int64 f7g7_38 = f7_2 * (Int64)g7_19;
      Int64 f7g8_19 = f7 * (Int64)g8_19;
      Int64 f7g9_38 = f7_2 * (Int64)g9_19;
      Int64 f8g0 = f8 * (Int64)g0;
      Int64 f8g1 = f8 * (Int64)g1;
      Int64 f8g2_19 = f8 * (Int64)g2_19;
      Int64 f8g3_19 = f8 * (Int64)g3_19;
      Int64 f8g4_19 = f8 * (Int64)g4_19;
      Int64 f8g5_19 = f8 * (Int64)g5_19;
      Int64 f8g6_19 = f8 * (Int64)g6_19;
      Int64 f8g7_19 = f8 * (Int64)g7_19;
      Int64 f8g8_19 = f8 * (Int64)g8_19;
      Int64 f8g9_19 = f8 * (Int64)g9_19;
      Int64 f9g0 = f9 * (Int64)g0;
      Int64 f9g1_38 = f9_2 * (Int64)g1_19;
      Int64 f9g2_19 = f9 * (Int64)g2_19;
      Int64 f9g3_38 = f9_2 * (Int64)g3_19;
      Int64 f9g4_19 = f9 * (Int64)g4_19;
      Int64 f9g5_38 = f9_2 * (Int64)g5_19;
      Int64 f9g6_19 = f9 * (Int64)g6_19;
      Int64 f9g7_38 = f9_2 * (Int64)g7_19;
      Int64 f9g8_19 = f9 * (Int64)g8_19;
      Int64 f9g9_38 = f9_2 * (Int64)g9_19;
      Int64 h0 = f0g0 + f1g9_38 + f2g8_19 + f3g7_38 + f4g6_19 + f5g5_38 + f6g4_19 + f7g3_38 + f8g2_19 + f9g1_38;
      Int64 h1 = f0g1 + f1g0 + f2g9_19 + f3g8_19 + f4g7_19 + f5g6_19 + f6g5_19 + f7g4_19 + f8g3_19 + f9g2_19;
      Int64 h2 = f0g2 + f1g1_2 + f2g0 + f3g9_38 + f4g8_19 + f5g7_38 + f6g6_19 + f7g5_38 + f8g4_19 + f9g3_38;
      Int64 h3 = f0g3 + f1g2 + f2g1 + f3g0 + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 + f9g4_19;
      Int64 h4 = f0g4 + f1g3_2 + f2g2 + f3g1_2 + f4g0 + f5g9_38 + f6g8_19 + f7g7_38 + f8g6_19 + f9g5_38;
      Int64 h5 = f0g5 + f1g4 + f2g3 + f3g2 + f4g1 + f5g0 + f6g9_19 + f7g8_19 + f8g7_19 + f9g6_19;
      Int64 h6 = f0g6 + f1g5_2 + f2g4 + f3g3_2 + f4g2 + f5g1_2 + f6g0 + f7g9_38 + f8g8_19 + f9g7_38;
      Int64 h7 = f0g7 + f1g6 + f2g5 + f3g4 + f4g3 + f5g2 + f6g1 + f7g0 + f8g9_19 + f9g8_19;
      Int64 h8 = f0g8 + f1g7_2 + f2g6 + f3g5_2 + f4g4 + f5g3_2 + f6g2 + f7g1_2 + f8g0 + f9g9_38;
      Int64 h9 = f0g9 + f1g8 + f2g7 + f3g6 + f4g5 + f5g4 + f6g3 + f7g2 + f8g1 + f9g0;
      Int64 carry0;
      Int64 carry1;
      Int64 carry2;
      Int64 carry3;
      Int64 carry4;
      Int64 carry5;
      Int64 carry6;
      Int64 carry7;
      Int64 carry8;
      Int64 carry9;

      /*
      |h0| <= (1.65*1.65*2^52*(1+19+19+19+19)+1.65*1.65*2^50*(38+38+38+38+38))
          i.e. |h0| <= 1.4*2^60; narrower ranges for h2, h4, h6, h8
      |h1| <= (1.65*1.65*2^51*(1+1+19+19+19+19+19+19+19+19))
          i.e. |h1| <= 1.7*2^59; narrower ranges for h3, h5, h7, h9
      */

      carry0 = (h0 + (Int64)(1 << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
      carry4 = (h4 + (Int64)(1 << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
      /* |h0| <= 2^25 */
      /* |h4| <= 2^25 */
      /* |h1| <= 1.71*2^59 */
      /* |h5| <= 1.71*2^59 */

      carry1 = (h1 + (Int64)(1 << 24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
      carry5 = (h5 + (Int64)(1 << 24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
      /* |h1| <= 2^24; from now on fits into int32 */
      /* |h5| <= 2^24; from now on fits into int32 */
      /* |h2| <= 1.41*2^60 */
      /* |h6| <= 1.41*2^60 */

      carry2 = (h2 + (Int64)(1 << 25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
      carry6 = (h6 + (Int64)(1 << 25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
      /* |h2| <= 2^25; from now on fits into int32 unchanged */
      /* |h6| <= 2^25; from now on fits into int32 unchanged */
      /* |h3| <= 1.71*2^59 */
      /* |h7| <= 1.71*2^59 */

      carry3 = (h3 + (Int64)(1 << 24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
      carry7 = (h7 + (Int64)(1 << 24)) >> 25; h8 += carry7; h7 -= carry7 << 25;
      /* |h3| <= 2^24; from now on fits into int32 unchanged */
      /* |h7| <= 2^24; from now on fits into int32 unchanged */
      /* |h4| <= 1.72*2^34 */
      /* |h8| <= 1.41*2^60 */

      carry4 = (h4 + (Int64)(1 << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
      carry8 = (h8 + (Int64)(1 << 25)) >> 26; h9 += carry8; h8 -= carry8 << 26;
      /* |h4| <= 2^25; from now on fits into int32 unchanged */
      /* |h8| <= 2^25; from now on fits into int32 unchanged */
      /* |h5| <= 1.01*2^24 */
      /* |h9| <= 1.71*2^59 */

      carry9 = (h9 + (Int64)(1 << 24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
      /* |h9| <= 2^24; from now on fits into int32 unchanged */
      /* |h0| <= 1.1*2^39 */

      carry0 = (h0 + (Int64)(1 << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
      /* |h0| <= 2^25; from now on fits into int32 unchanged */
      /* |h1| <= 1.01*2^24 */

      h[0] = (Int32)h0;
      h[1] = (Int32)h1;
      h[2] = (Int32)h2;
      h[3] = (Int32)h3;
      h[4] = (Int32)h4;
      h[5] = (Int32)h5;
      h[6] = (Int32)h6;
      h[7] = (Int32)h7;
      h[8] = (Int32)h8;
      h[9] = (Int32)h9;
    }


    public static void FeSq(ref Int32[] h, Int32[] f)
    {
      Int32 f0 = f[0];
      Int32 f1 = f[1];
      Int32 f2 = f[2];
      Int32 f3 = f[3];
      Int32 f4 = f[4];
      Int32 f5 = f[5];
      Int32 f6 = f[6];
      Int32 f7 = f[7];
      Int32 f8 = f[8];
      Int32 f9 = f[9];
      Int32 f0_2 = 2 * f0;
      Int32 f1_2 = 2 * f1;
      Int32 f2_2 = 2 * f2;
      Int32 f3_2 = 2 * f3;
      Int32 f4_2 = 2 * f4;
      Int32 f5_2 = 2 * f5;
      Int32 f6_2 = 2 * f6;
      Int32 f7_2 = 2 * f7;
      Int32 f5_38 = 38 * f5; /* 1.959375*2^30 */
      Int32 f6_19 = 19 * f6; /* 1.959375*2^30 */
      Int32 f7_38 = 38 * f7; /* 1.959375*2^30 */
      Int32 f8_19 = 19 * f8; /* 1.959375*2^30 */
      Int32 f9_38 = 38 * f9; /* 1.959375*2^30 */
      Int64 f0f0 = f0 * (Int64)f0;
      Int64 f0f1_2 = f0_2 * (Int64)f1;
      Int64 f0f2_2 = f0_2 * (Int64)f2;
      Int64 f0f3_2 = f0_2 * (Int64)f3;
      Int64 f0f4_2 = f0_2 * (Int64)f4;
      Int64 f0f5_2 = f0_2 * (Int64)f5;
      Int64 f0f6_2 = f0_2 * (Int64)f6;
      Int64 f0f7_2 = f0_2 * (Int64)f7;
      Int64 f0f8_2 = f0_2 * (Int64)f8;
      Int64 f0f9_2 = f0_2 * (Int64)f9;
      Int64 f1f1_2 = f1_2 * (Int64)f1;
      Int64 f1f2_2 = f1_2 * (Int64)f2;
      Int64 f1f3_4 = f1_2 * (Int64)f3_2;
      Int64 f1f4_2 = f1_2 * (Int64)f4;
      Int64 f1f5_4 = f1_2 * (Int64)f5_2;
      Int64 f1f6_2 = f1_2 * (Int64)f6;
      Int64 f1f7_4 = f1_2 * (Int64)f7_2;
      Int64 f1f8_2 = f1_2 * (Int64)f8;
      Int64 f1f9_76 = f1_2 * (Int64)f9_38;
      Int64 f2f2 = f2 * (Int64)f2;
      Int64 f2f3_2 = f2_2 * (Int64)f3;
      Int64 f2f4_2 = f2_2 * (Int64)f4;
      Int64 f2f5_2 = f2_2 * (Int64)f5;
      Int64 f2f6_2 = f2_2 * (Int64)f6;
      Int64 f2f7_2 = f2_2 * (Int64)f7;
      Int64 f2f8_38 = f2_2 * (Int64)f8_19;
      Int64 f2f9_38 = f2 * (Int64)f9_38;
      Int64 f3f3_2 = f3_2 * (Int64)f3;
      Int64 f3f4_2 = f3_2 * (Int64)f4;
      Int64 f3f5_4 = f3_2 * (Int64)f5_2;
      Int64 f3f6_2 = f3_2 * (Int64)f6;
      Int64 f3f7_76 = f3_2 * (Int64)f7_38;
      Int64 f3f8_38 = f3_2 * (Int64)f8_19;
      Int64 f3f9_76 = f3_2 * (Int64)f9_38;
      Int64 f4f4 = f4 * (Int64)f4;
      Int64 f4f5_2 = f4_2 * (Int64)f5;
      Int64 f4f6_38 = f4_2 * (Int64)f6_19;
      Int64 f4f7_38 = f4 * (Int64)f7_38;
      Int64 f4f8_38 = f4_2 * (Int64)f8_19;
      Int64 f4f9_38 = f4 * (Int64)f9_38;
      Int64 f5f5_38 = f5 * (Int64)f5_38;
      Int64 f5f6_38 = f5_2 * (Int64)f6_19;
      Int64 f5f7_76 = f5_2 * (Int64)f7_38;
      Int64 f5f8_38 = f5_2 * (Int64)f8_19;
      Int64 f5f9_76 = f5_2 * (Int64)f9_38;
      Int64 f6f6_19 = f6 * (Int64)f6_19;
      Int64 f6f7_38 = f6 * (Int64)f7_38;
      Int64 f6f8_38 = f6_2 * (Int64)f8_19;
      Int64 f6f9_38 = f6 * (Int64)f9_38;
      Int64 f7f7_38 = f7 * (Int64)f7_38;
      Int64 f7f8_38 = f7_2 * (Int64)f8_19;
      Int64 f7f9_76 = f7_2 * (Int64)f9_38;
      Int64 f8f8_19 = f8 * (Int64)f8_19;
      Int64 f8f9_38 = f8 * (Int64)f9_38;
      Int64 f9f9_38 = f9 * (Int64)f9_38;
      Int64 h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
      Int64 h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
      Int64 h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
      Int64 h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
      Int64 h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
      Int64 h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
      Int64 h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
      Int64 h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
      Int64 h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
      Int64 h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;
      Int64 carry0;
      Int64 carry1;
      Int64 carry2;
      Int64 carry3;
      Int64 carry4;
      Int64 carry5;
      Int64 carry6;
      Int64 carry7;
      Int64 carry8;
      Int64 carry9;

      carry0 = (h0 + (Int64)(1 << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
      carry4 = (h4 + (Int64)(1 << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;

      carry1 = (h1 + (Int64)(1 << 24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
      carry5 = (h5 + (Int64)(1 << 24)) >> 25; h6 += carry5; h5 -= carry5 << 25;

      carry2 = (h2 + (Int64)(1 << 25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
      carry6 = (h6 + (Int64)(1 << 25)) >> 26; h7 += carry6; h6 -= carry6 << 26;

      carry3 = (h3 + (Int64)(1 << 24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
      carry7 = (h7 + (Int64)(1 << 24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

      carry4 = (h4 + (Int64)(1 << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
      carry8 = (h8 + (Int64)(1 << 25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

      carry9 = (h9 + (Int64)(1 << 24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;

      carry0 = (h0 + (Int64)(1 << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;

      h[0] = (Int32)h0;
      h[1] = (Int32)h1;
      h[2] = (Int32)h2;
      h[3] = (Int32)h3;
      h[4] = (Int32)h4;
      h[5] = (Int32)h5;
      h[6] = (Int32)h6;
      h[7] = (Int32)h7;
      h[8] = (Int32)h8;
      h[9] = (Int32)h9;
    }
    public static int FeIsnegative(Int32[] f)
    {
      byte[] s = new byte[32];
      FeTobytes(ref s, f);
      return s[0] & 1;
    }
    public static void FeInvert(ref Int32[] res, Int32[] z)
    {
      Int32[] t0 = new Int32[10];
      Int32[] t1 = new Int32[10];
      Int32[] t2 = new Int32[10];
      Int32[] t3 = new Int32[10];
      int i;

      FeSq(ref t0, z);
      FeSq(ref t1, t0);
      FeSq(ref t1, t1);
      FeMul(ref t1, z, t1);
      FeMul(ref t0, t0, t1);
      FeSq(ref t2, t0);
      FeMul(ref t1, t1, t2);
      FeSq(ref t2, t1);
      for (i = 0; i < 4; ++i)
      {
        FeSq(ref t2, t2);
      }
      FeMul(ref t1, t2, t1);
      FeSq(ref t2, t1);
      for (i = 0; i < 9; ++i)
      {
        FeSq(ref t2, t2);
      }
      FeMul(ref t2, t2, t1);
      FeSq(ref t3, t2);
      for (i = 0; i < 19; ++i)
      {
        FeSq(ref t3, t3);
      }
      FeMul(ref t2, t3, t2);
      FeSq(ref t2, t2);
      for (i = 0; i < 9; ++i)
      {
        FeSq(ref t2, t2);
      }
      FeMul(ref t1, t2, t1);
      FeSq(ref t2, t1);
      for (i = 0; i < 49; ++i)
      {
        FeSq(ref t2, t2);
      }
      FeMul(ref t2, t2, t1);
      FeSq(ref t3, t2);
      for (i = 0; i < 99; ++i)
      {
        FeSq(ref t3, t3);
      }
      FeMul(ref t2, t3, t2);
      FeSq(ref t2, t2);
      for (i = 0; i < 49; ++i)
      {
        FeSq(ref t2, t2);
      }
      FeMul(ref t1, t2, t1);
      FeSq(ref t1, t1);
      for (i = 0; i < 4; ++i)
      {
        FeSq(ref t1, t1);
      }
      FeMul(ref res, t1, t0);

      return;
    }

    public static void FeSq2(ref Int32[] h, Int32[] f)
    {
      Int32 f0 = f[0];
      Int32 f1 = f[1];
      Int32 f2 = f[2];
      Int32 f3 = f[3];
      Int32 f4 = f[4];
      Int32 f5 = f[5];
      Int32 f6 = f[6];
      Int32 f7 = f[7];
      Int32 f8 = f[8];
      Int32 f9 = f[9];
      Int32 f0_2 = 2 * f0;
      Int32 f1_2 = 2 * f1;
      Int32 f2_2 = 2 * f2;
      Int32 f3_2 = 2 * f3;
      Int32 f4_2 = 2 * f4;
      Int32 f5_2 = 2 * f5;
      Int32 f6_2 = 2 * f6;
      Int32 f7_2 = 2 * f7;
      Int32 f5_38 = 38 * f5; /* 1.959375*2^30 */
      Int32 f6_19 = 19 * f6; /* 1.959375*2^30 */
      Int32 f7_38 = 38 * f7; /* 1.959375*2^30 */
      Int32 f8_19 = 19 * f8; /* 1.959375*2^30 */
      Int32 f9_38 = 38 * f9; /* 1.959375*2^30 */
      Int64 f0f0 = f0 * (Int64)f0;
      Int64 f0f1_2 = f0_2 * (Int64)f1;
      Int64 f0f2_2 = f0_2 * (Int64)f2;
      Int64 f0f3_2 = f0_2 * (Int64)f3;
      Int64 f0f4_2 = f0_2 * (Int64)f4;
      Int64 f0f5_2 = f0_2 * (Int64)f5;
      Int64 f0f6_2 = f0_2 * (Int64)f6;
      Int64 f0f7_2 = f0_2 * (Int64)f7;
      Int64 f0f8_2 = f0_2 * (Int64)f8;
      Int64 f0f9_2 = f0_2 * (Int64)f9;
      Int64 f1f1_2 = f1_2 * (Int64)f1;
      Int64 f1f2_2 = f1_2 * (Int64)f2;
      Int64 f1f3_4 = f1_2 * (Int64)f3_2;
      Int64 f1f4_2 = f1_2 * (Int64)f4;
      Int64 f1f5_4 = f1_2 * (Int64)f5_2;
      Int64 f1f6_2 = f1_2 * (Int64)f6;
      Int64 f1f7_4 = f1_2 * (Int64)f7_2;
      Int64 f1f8_2 = f1_2 * (Int64)f8;
      Int64 f1f9_76 = f1_2 * (Int64)f9_38;
      Int64 f2f2 = f2 * (Int64)f2;
      Int64 f2f3_2 = f2_2 * (Int64)f3;
      Int64 f2f4_2 = f2_2 * (Int64)f4;
      Int64 f2f5_2 = f2_2 * (Int64)f5;
      Int64 f2f6_2 = f2_2 * (Int64)f6;
      Int64 f2f7_2 = f2_2 * (Int64)f7;
      Int64 f2f8_38 = f2_2 * (Int64)f8_19;
      Int64 f2f9_38 = f2 * (Int64)f9_38;
      Int64 f3f3_2 = f3_2 * (Int64)f3;
      Int64 f3f4_2 = f3_2 * (Int64)f4;
      Int64 f3f5_4 = f3_2 * (Int64)f5_2;
      Int64 f3f6_2 = f3_2 * (Int64)f6;
      Int64 f3f7_76 = f3_2 * (Int64)f7_38;
      Int64 f3f8_38 = f3_2 * (Int64)f8_19;
      Int64 f3f9_76 = f3_2 * (Int64)f9_38;
      Int64 f4f4 = f4 * (Int64)f4;
      Int64 f4f5_2 = f4_2 * (Int64)f5;
      Int64 f4f6_38 = f4_2 * (Int64)f6_19;
      Int64 f4f7_38 = f4 * (Int64)f7_38;
      Int64 f4f8_38 = f4_2 * (Int64)f8_19;
      Int64 f4f9_38 = f4 * (Int64)f9_38;
      Int64 f5f5_38 = f5 * (Int64)f5_38;
      Int64 f5f6_38 = f5_2 * (Int64)f6_19;
      Int64 f5f7_76 = f5_2 * (Int64)f7_38;
      Int64 f5f8_38 = f5_2 * (Int64)f8_19;
      Int64 f5f9_76 = f5_2 * (Int64)f9_38;
      Int64 f6f6_19 = f6 * (Int64)f6_19;
      Int64 f6f7_38 = f6 * (Int64)f7_38;
      Int64 f6f8_38 = f6_2 * (Int64)f8_19;
      Int64 f6f9_38 = f6 * (Int64)f9_38;
      Int64 f7f7_38 = f7 * (Int64)f7_38;
      Int64 f7f8_38 = f7_2 * (Int64)f8_19;
      Int64 f7f9_76 = f7_2 * (Int64)f9_38;
      Int64 f8f8_19 = f8 * (Int64)f8_19;
      Int64 f8f9_38 = f8 * (Int64)f9_38;
      Int64 f9f9_38 = f9 * (Int64)f9_38;
      Int64 h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
      Int64 h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
      Int64 h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
      Int64 h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
      Int64 h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
      Int64 h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
      Int64 h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
      Int64 h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
      Int64 h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
      Int64 h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;
      Int64 carry0;
      Int64 carry1;
      Int64 carry2;
      Int64 carry3;
      Int64 carry4;
      Int64 carry5;
      Int64 carry6;
      Int64 carry7;
      Int64 carry8;
      Int64 carry9;

      h0 += h0;
      h1 += h1;
      h2 += h2;
      h3 += h3;
      h4 += h4;
      h5 += h5;
      h6 += h6;
      h7 += h7;
      h8 += h8;
      h9 += h9;

      carry0 = (h0 + (Int64)(1 << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
      carry4 = (h4 + (Int64)(1 << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;

      carry1 = (h1 + (Int64)(1 << 24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
      carry5 = (h5 + (Int64)(1 << 24)) >> 25; h6 += carry5; h5 -= carry5 << 25;

      carry2 = (h2 + (Int64)(1 << 25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
      carry6 = (h6 + (Int64)(1 << 25)) >> 26; h7 += carry6; h6 -= carry6 << 26;

      carry3 = (h3 + (Int64)(1 << 24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
      carry7 = (h7 + (Int64)(1 << 24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

      carry4 = (h4 + (Int64)(1 << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
      carry8 = (h8 + (Int64)(1 << 25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

      carry9 = (h9 + (Int64)(1 << 24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;

      carry0 = (h0 + (Int64)(1 << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;

      h[0] = (Int32)h0;
      h[1] = (Int32)h1;
      h[2] = (Int32)h2;
      h[3] = (Int32)h3;
      h[4] = (Int32)h4;
      h[5] = (Int32)h5;
      h[6] = (Int32)h6;
      h[7] = (Int32)h7;
      h[8] = (Int32)h8;
      h[9] = (Int32)h9;
    }

    public static void FeAdd(ref Int32[] h, Int32[] f, Int32[] g)
    {
      Int32 f0 = f[0];
      Int32 f1 = f[1];
      Int32 f2 = f[2];
      Int32 f3 = f[3];
      Int32 f4 = f[4];
      Int32 f5 = f[5];
      Int32 f6 = f[6];
      Int32 f7 = f[7];
      Int32 f8 = f[8];
      Int32 f9 = f[9];
      Int32 g0 = g[0];
      Int32 g1 = g[1];
      Int32 g2 = g[2];
      Int32 g3 = g[3];
      Int32 g4 = g[4];
      Int32 g5 = g[5];
      Int32 g6 = g[6];
      Int32 g7 = g[7];
      Int32 g8 = g[8];
      Int32 g9 = g[9];
      Int32 h0 = f0 + g0;
      Int32 h1 = f1 + g1;
      Int32 h2 = f2 + g2;
      Int32 h3 = f3 + g3;
      Int32 h4 = f4 + g4;
      Int32 h5 = f5 + g5;
      Int32 h6 = f6 + g6;
      Int32 h7 = f7 + g7;
      Int32 h8 = f8 + g8;
      Int32 h9 = f9 + g9;
      h[0] = h0;
      h[1] = h1;
      h[2] = h2;
      h[3] = h3;
      h[4] = h4;
      h[5] = h5;
      h[6] = h6;
      h[7] = h7;
      h[8] = h8;
      h[9] = h9;
    }

    public static void Fe0(ref Int32[] h)
    {
      h[0] = 0;
      h[1] = 0;
      h[2] = 0;
      h[3] = 0;
      h[4] = 0;
      h[5] = 0;
      h[6] = 0;
      h[7] = 0;
      h[8] = 0;
      h[9] = 0;
    }

    public static void Fe1(ref Int32[] h)
    {
      h[0] = 1;
      h[1] = 0;
      h[2] = 0;
      h[3] = 0;
      h[4] = 0;
      h[5] = 0;
      h[6] = 0;
      h[7] = 0;
      h[8] = 0;
      h[9] = 0;
    }

    public static void FeDivpowm1(ref Int32[] r, Int32[] u, Int32[] v)
    {
      Int32[] v3 = new Int32[10];
      Int32[] uv7 = new Int32[10];
      Int32[] t0 = new Int32[10];
      Int32[] t1 = new Int32[10];
      Int32[] t2 = new Int32[10];
      int i;

      FeSq(ref v3, v);
      FeMul(ref v3, v3, v); /* v3 = v^3 */
      FeSq(ref uv7, v3);
      FeMul(ref uv7, uv7, v);
      FeMul(ref uv7, uv7, u); /* uv7 = uv^7 */

      /*fe_pow22523(uv7, uv7);*/

      /* From fe_pow22523.c */

      FeSq(ref t0, uv7);
      FeSq(ref t1, t0);
      FeSq(ref t1, t1);
      FeMul(ref t1, uv7, t1);
      FeMul(ref t0, t0, t1);
      FeSq(ref t0, t0);
      FeMul(ref t0, t1, t0);
      FeSq(ref t1, t0);
      for (i = 0; i < 4; ++i)
      {
        FeSq(ref t1, t1);
      }
      FeMul(ref t0, t1, t0);
      FeSq(ref t1, t0);
      for (i = 0; i < 9; ++i)
      {
        FeSq(ref t1, t1);
      }
      FeMul(ref t1, t1, t0);
      FeSq(ref t2, t1);
      for (i = 0; i < 19; ++i)
      {
        FeSq(ref t2, t2);
      }
      FeMul(ref t1, t2, t1);
      for (i = 0; i < 10; ++i)
      {
        FeSq(ref t1, t1);
      }
      FeMul(ref t0, t1, t0);
      FeSq(ref t1, t0);
      for (i = 0; i < 49; ++i)
      {
        FeSq(ref t1, t1);
      }
      FeMul(ref t1, t1, t0);
      FeSq(ref t2, t1);
      for (i = 0; i < 99; ++i)
      {
        FeSq(ref t2, t2);
      }
      FeMul(ref t1, t2, t1);
      for (i = 0; i < 50; ++i)
      {
        FeSq(ref t1, t1);
      }
      FeMul(ref t0, t1, t0);
      FeSq(ref t0, t0);
      FeSq(ref t0, t0);
      FeMul(ref t0, t0, uv7);

      /* End fe_pow22523.c */
      /* t0 = (uv^7)^((q-5)/8) */
      FeMul(ref t0, t0, v3);
      FeMul(ref r, t0, u); /* u^(m+1)v^(-(m+1)) */
    }

    static void FeSub(ref Int32[] h, Int32[] f, Int32[] g)
    {
      Int32 f0 = f[0];
      Int32 f1 = f[1];
      Int32 f2 = f[2];
      Int32 f3 = f[3];
      Int32 f4 = f[4];
      Int32 f5 = f[5];
      Int32 f6 = f[6];
      Int32 f7 = f[7];
      Int32 f8 = f[8];
      Int32 f9 = f[9];
      Int32 g0 = g[0];
      Int32 g1 = g[1];
      Int32 g2 = g[2];
      Int32 g3 = g[3];
      Int32 g4 = g[4];
      Int32 g5 = g[5];
      Int32 g6 = g[6];
      Int32 g7 = g[7];
      Int32 g8 = g[8];
      Int32 g9 = g[9];
      Int32 h0 = f0 - g0;
      Int32 h1 = f1 - g1;
      Int32 h2 = f2 - g2;
      Int32 h3 = f3 - g3;
      Int32 h4 = f4 - g4;
      Int32 h5 = f5 - g5;
      Int32 h6 = f6 - g6;
      Int32 h7 = f7 - g7;
      Int32 h8 = f8 - g8;
      Int32 h9 = f9 - g9;
      h[0] = h0;
      h[1] = h1;
      h[2] = h2;
      h[3] = h3;
      h[4] = h4;
      h[5] = h5;
      h[6] = h6;
      h[7] = h7;
      h[8] = h8;
      h[9] = h9;
    }

    public static void FeCopy(ref Int32[] h, Int32[] f)
    {
      Int32 f0 = f[0];
      Int32 f1 = f[1];
      Int32 f2 = f[2];
      Int32 f3 = f[3];
      Int32 f4 = f[4];
      Int32 f5 = f[5];
      Int32 f6 = f[6];
      Int32 f7 = f[7];
      Int32 f8 = f[8];
      Int32 f9 = f[9];
      h[0] = f0;
      h[1] = f1;
      h[2] = f2;
      h[3] = f3;
      h[4] = f4;
      h[5] = f5;
      h[6] = f6;
      h[7] = f7;
      h[8] = f8;
      h[9] = f9;
    }

    static bool FeIsnonzero(ref Int32[] f)
    {
      byte[] s = new byte[32];
      FeTobytes(ref s, f);
      return ((((int)(s[0] | s[1] | s[2] | s[3] | s[4] | s[5] | s[6] | s[7] | s[8] |
        s[9] | s[10] | s[11] | s[12] | s[13] | s[14] | s[15] | s[16] | s[17] |
        s[18] | s[19] | s[20] | s[21] | s[22] | s[23] | s[24] | s[25] | s[26] |
        s[27] | s[28] | s[29] | s[30] | s[31]) - 1) >> 8) + 1) != 0;
    }

    public static void FeNeg(ref Int32[] h, Int32[] f)
    {
      Int32 f0 = f[0];
      Int32 f1 = f[1];
      Int32 f2 = f[2];
      Int32 f3 = f[3];
      Int32 f4 = f[4];
      Int32 f5 = f[5];
      Int32 f6 = f[6];
      Int32 f7 = f[7];
      Int32 f8 = f[8];
      Int32 f9 = f[9];
      Int32 h0 = -f0;
      Int32 h1 = -f1;
      Int32 h2 = -f2;
      Int32 h3 = -f3;
      Int32 h4 = -f4;
      Int32 h5 = -f5;
      Int32 h6 = -f6;
      Int32 h7 = -f7;
      Int32 h8 = -f8;
      Int32 h9 = -f9;
      h[0] = h0;
      h[1] = h1;
      h[2] = h2;
      h[3] = h3;
      h[4] = h4;
      h[5] = h5;
      h[6] = h6;
      h[7] = h7;
      h[8] = h8;
      h[9] = h9;
    }

    public static void GeFromfeFrombytesVartime(ref GeP2 r, byte[] s)
    {
      Int32[] u = new Int32[10];
      Int32[] v = new Int32[10];
      Int32[] w = new Int32[10];
      Int32[] x = new Int32[10];
      Int32[] y = new Int32[10];
      Int32[] z = new Int32[10];
      byte sign;

      /* From fe_frombytes.c */

      Int64 h0 = (Int64)(Load4(s));
      Int64 h1 = (Int64)(Load3(s.SubArray(4)) << 6);
      Int64 h2 = (Int64)(Load3(s.SubArray(7)) << 5);
      Int64 h3 = (Int64)(Load3(s.SubArray(10)) << 3);
      Int64 h4 = (Int64)(Load3(s.SubArray(13)) << 2);
      Int64 h5 = (Int64)(Load4(s.SubArray(16)));
      Int64 h6 = (Int64)(Load3(s.SubArray(20)) << 7);
      Int64 h7 = (Int64)(Load3(s.SubArray(23)) << 5);
      Int64 h8 = (Int64)(Load3(s.SubArray(26)) << 4);
      Int64 h9 = (Int64)(Load3(s.SubArray(29)) << 2);
      Int64 carry0;
      Int64 carry1;
      Int64 carry2;
      Int64 carry3;
      Int64 carry4;
      Int64 carry5;
      Int64 carry6;
      Int64 carry7;
      Int64 carry8;
      Int64 carry9;

      carry9 = (h9 + (Int64)(1 << 24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
      carry1 = (h1 + (Int64)(1 << 24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
      carry3 = (h3 + (Int64)(1 << 24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
      carry5 = (h5 + (Int64)(1 << 24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
      carry7 = (h7 + (Int64)(1 << 24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

      carry0 = (h0 + (Int64)(1 << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
      carry2 = (h2 + (Int64)(1 << 25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
      carry4 = (h4 + (Int64)(1 << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
      carry6 = (h6 + (Int64)(1 << 25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
      carry8 = (h8 + (Int64)(1 << 25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

      u[0] = (Int32)h0;
      u[1] = (Int32)h1;
      u[2] = (Int32)h2;
      u[3] = (Int32)h3;
      u[4] = (Int32)h4;
      u[5] = (Int32)h5;
      u[6] = (Int32)h6;
      u[7] = (Int32)h7;
      u[8] = (Int32)h8;
      u[9] = (Int32)h9;

      /* End fe_frombytes.c */

      FeSq2(ref v, u); /* 2 * u^2 */
      Fe1(ref w);
      FeAdd(ref w, v, w); /* w = 2 * u^2 + 1 */
      FeSq(ref x, w); /* w^2 */
      FeMul(ref y, FeMa2, v); /* -2 * A^2 * u^2 */
      FeAdd(ref x, x, y); /* x = w^2 - 2 * A^2 * u^2 */
      FeDivpowm1(ref r.X, w, x); /* (w / x)^(m + 1) */
      FeSq(ref y, r.X);
      FeMul(ref x, y, x);
      FeSub(ref y, w, x);
      FeCopy(ref z, FeMa);
      if (FeIsnonzero(ref y))
      {
        FeAdd(ref y, w, x);
        if (FeIsnonzero(ref y))
        {
          goto negative;
        }
        else
        {
          FeMul(ref r.X, r.X, FeFffb1);
        }
      }
      else
      {
        FeMul(ref r.X, r.X, fe_fffb2);
      }
      FeMul(ref r.X, r.X, u); /* u * sqrt(2 * A * (A + 2) * w / x) */
      FeMul(ref z, z, v); /* -2 * A * u^2 */
      sign = 0;
      goto setsign;
      negative:
      FeMul(ref x, x, fe_sqrtm1);
      FeSub(ref y, w, x);
      if (FeIsnonzero(ref y))
      {
        //assert((FeAdd(ref y, w, x), !FeIsnonzero(ref y)));
        FeMul(ref r.X, r.X, fe_fffb3);
      }
      else
      {
        FeMul(ref r.X, r.X, fe_fffb4);
      }
      /* r->X = sqrt(A * (A + 2) * w / x) */
      /* z = -A */
      sign = 1;
      setsign:
      if (FeIsnegative(r.X) != sign)
      {
        if (!FeIsnonzero(ref r.X))
        {
          throw new Exception("");
        }
        //assert();
        FeNeg(ref r.X, r.X);
      }
      FeAdd(ref r.Z, z, w);
      FeSub(ref r.Y, z, w);
      FeMul(ref r.X, r.X, r.Z);

      {
        Int32[] check_x = new Int32[10];
        Int32[] check_y = new Int32[10];
        Int32[] check_iz = new Int32[10];
        Int32[] check_v = new Int32[10];
        FeInvert(ref check_iz, r.Z);
        FeMul(ref check_x, r.X, check_iz);
        FeMul(ref check_y, r.Y, check_iz);
        FeSq(ref check_x, check_x);
        FeSq(ref check_y, check_y);
        FeMul(ref check_v, check_x, check_y);
        FeMul(ref check_v, FeD, check_v);
        FeAdd(ref check_v, check_v, check_x);
        FeSub(ref check_v, check_v, check_y);
        Fe1(ref check_x);
        FeAdd(ref check_v, check_v, check_x);
        if (FeIsnonzero(ref check_v))
        {
          throw new Exception("somthing wrong with GeFromfeFrombytesVartime");
        }
      }
    }

    public static void GeP2Dbl(ref GeP1P1 r, GeP2 p)
    {
      Int32[] t0 = new Int32[10];
      FeSq(ref r.X, p.X);
      FeSq(ref r.Z, p.Y);
      FeSq2(ref r.T, p.Z);
      FeAdd(ref r.Y, p.X, p.Y);
      FeSq(ref t0, r.Y);
      FeAdd(ref r.Y, r.Z, r.X);
      FeSub(ref r.Z, r.Z, r.X);
      FeSub(ref r.X, t0, r.Y);
      FeSub(ref r.T, r.T, r.Z);
    }

    public static void GeP1P1ToP2(ref GeP2 r, GeP1P1 p)
    {
      FeMul(ref r.X, p.X, p.T);
      FeMul(ref r.Y, p.Y, p.Z);
      FeMul(ref r.Z, p.Z, p.T);
    }

    public static void GeP1P1ToP3(ref GeP3 r, GeP1P1 p)
    {
      FeMul(ref r.X, p.X, p.T);
      FeMul(ref r.Y, p.Y, p.Z);
      FeMul(ref r.Z, p.Z, p.T);
      FeMul(ref r.T, p.X, p.Y);
    }

    public static void GeMul8(ref GeP1P1 r, GeP2 t)
    {
      GeP2 u = new GeP2();
      GeP2Dbl(ref r, t);
      GeP1P1ToP2(ref u, r);
      GeP2Dbl(ref r, u);
      GeP1P1ToP2(ref u, r);
      GeP2Dbl(ref r, u);
    }

    public static GeP3 HashToEc(byte[] key)
    {
      byte[] hash = CnFastHash(key);
      GeP2 gep2 = new GeP2();
      GeP1P1 gep1p1 = new GeP1P1();
      GeP3 gep3 = new GeP3();

      GeFromfeFrombytesVartime(ref gep2, hash);
      GeMul8(ref gep1p1, gep2);
      GeP1P1ToP3(ref gep3, gep1p1);

      return gep3;
    }

    public static void GeP3ToBytes(ref byte[] s, GeP3 h)
    {
      Int32[] recip = new Int32[10];
      Int32[] x = new Int32[10];
      Int32[] y = new Int32[10];

      FeInvert(ref recip, h.Z);
      FeMul(ref x, h.X, recip);
      FeMul(ref y, h.Y, recip);
      FeTobytes(ref s, y);
      s[31] ^= (byte)(FeIsnegative(x) << 7);
    }

    public static void GeP3ToCached(ref GeCached r, GeP3 p)
    {
      FeAdd(ref r.YplusX, p.Y, p.X);
      FeSub(ref r.YminusX, p.Y, p.X);
      FeCopy(ref r.Z, p.Z);
      FeMul(ref r.T2d, p.T, FeD2);
    }

    public static byte[] GenerateKeyImage2(byte[] pub, byte[] sec)
    {
      if (pub.Length != 32 || sec.Length != 32)
      {
        throw new Exception("Invalid input length");
      }

      if (ScCheck(sec) != 0)
      {
        throw new Exception("sc_check(sec) != 0");
      }

      GeP3 gep3 = HashToEc(pub);
      GeP2 gep2 = new GeP2();

      //GeP3 gep3 = new GeP3();
      GeScalarmult(ref gep2, sec, gep3);

      byte[] image = new byte[32];
      GeTobytes(ref image, gep2);
      return image;
    }

    public static void GeAdd(ref GeP1P1 r, GeP3 p, GeCached q)
    {
      Int32[] t0 = new Int32[10];

      FeAdd(ref r.X, p.Y, p.X);
      FeSub(ref r.Y, p.Y, p.X);
      FeMul(ref r.Z, r.X, q.YplusX);
      FeMul(ref r.Y, r.Y, q.YminusX);
      FeMul(ref r.T, q.T2d, p.T);
      FeMul(ref r.X, p.Z, q.Z);
      FeAdd(ref t0, r.X, r.X);
      FeSub(ref r.X, r.Z, r.Y);
      FeAdd(ref r.Y, r.Z, r.Y);
      FeAdd(ref r.Z, t0, r.T);
      FeSub(ref r.T, t0, r.T);
    }

    static void GeP20(ref GeP2 h)
    {
      Fe0(ref h.X);
      Fe1(ref h.Y);
      Fe1(ref h.Z);
    }

    static void FeCmov(ref Int32[] f, Int32[] g, uint b)
    {
      Int32 f0 = f[0];
      Int32 f1 = f[1];
      Int32 f2 = f[2];
      Int32 f3 = f[3];
      Int32 f4 = f[4];
      Int32 f5 = f[5];
      Int32 f6 = f[6];
      Int32 f7 = f[7];
      Int32 f8 = f[8];
      Int32 f9 = f[9];
      Int32 g0 = g[0];
      Int32 g1 = g[1];
      Int32 g2 = g[2];
      Int32 g3 = g[3];
      Int32 g4 = g[4];
      Int32 g5 = g[5];
      Int32 g6 = g[6];
      Int32 g7 = g[7];
      Int32 g8 = g[8];
      Int32 g9 = g[9];
      Int32 x0 = f0 ^ g0;
      Int32 x1 = f1 ^ g1;
      Int32 x2 = f2 ^ g2;
      Int32 x3 = f3 ^ g3;
      Int32 x4 = f4 ^ g4;
      Int32 x5 = f5 ^ g5;
      Int32 x6 = f6 ^ g6;
      Int32 x7 = f7 ^ g7;
      Int32 x8 = f8 ^ g8;
      Int32 x9 = f9 ^ g9;
      if ((((b - 1) & ~b) | ((b - 2) & ~(b - 1))) != 4294967295 /*2^32 - 1*/)
      {
        throw new Exception("((((b - 1) & ~b) | ((b - 2) & ~(b - 1))) != 4294967295 /*2^32 - 1*/)");
      }

      b = (UInt32)(-b);
      x0 &= (Int32)b;
      x1 &= (Int32)b;
      x2 &= (Int32)b;
      x3 &= (Int32)b;
      x4 &= (Int32)b;
      x5 &= (Int32)b;
      x6 &= (Int32)b;
      x7 &= (Int32)b;
      x8 &= (Int32)b;
      x9 &= (Int32)b;
      f[0] = f0 ^ x0;
      f[1] = f1 ^ x1;
      f[2] = f2 ^ x2;
      f[3] = f3 ^ x3;
      f[4] = f4 ^ x4;
      f[5] = f5 ^ x5;
      f[6] = f6 ^ x6;
      f[7] = f7 ^ x7;
      f[8] = f8 ^ x8;
      f[9] = f9 ^ x9;
    }

    static void GeCachedCmov(ref GeCached t, GeCached u, byte b)
    {
      FeCmov(ref t.YplusX, u.YplusX, b);
      FeCmov(ref t.YminusX, u.YminusX, b);
      FeCmov(ref t.Z, u.Z, b);
      FeCmov(ref t.T2d, u.T2d, b);
    }

    static byte Negative(sbyte b)
    {
      UInt64 x = (UInt64)b; /* 18446744073709551361..18446744073709551615: yes; 0..255: no */
      x >>= 63; /* 1: yes; 0: no */
      return (byte)x;
    }

    public static void GeCached0(ref GeCached r)
    {
      Fe1(ref r.YplusX);
      Fe1(ref r.YminusX);
      Fe1(ref r.Z);
      Fe0(ref r.T2d);
    }

    static byte Equal(sbyte b, sbyte c)
    {
      sbyte ub = b;
      sbyte uc = c;
      sbyte x = (sbyte)(ub ^ uc); /* 0: yes; 1..255: no */
      UInt32 y = (UInt32)x; /* 0: yes; 1..255: no */
      y -= 1; /* 4294967295: yes; 0..254: no */
      y >>= 31; /* 1: yes; 0: no */
      return (byte)y;
    }

    public static void GeScalarmult(ref GeP2 r, byte[] a, GeP3 A)
    {
      sbyte[] e = new sbyte[64];
      int carry, carry2, i;
      GeCached[] Ai = new GeCached[8];  /* 1 * A, 2 * A, ..., 8 * A */

      for (int j = 0; j < 8; ++j)
      {
        Ai[j] = new GeCached();
      }

      GeP1P1 t = new GeP1P1();
      GeP3 u = new GeP3();

      carry = 0; /* 0..1 */
      for (i = 0; i < 31; i++)
      {
        carry += a[i]; /* 0..256 */
        carry2 = (carry + 8) >> 4; /* 0..16 */
        e[2 * i] = (sbyte)(carry - (carry2 << 4)); /* -8..7 */
        carry = (carry2 + 8) >> 4; /* 0..1 */
        e[2 * i + 1] = (sbyte)(carry2 - (carry << 4)); /* -8..7 */
      }
      carry += a[31]; /* 0..128 */
      carry2 = (carry + 8) >> 4; /* 0..8 */
      e[62] = (sbyte)(carry - (carry2 << 4)); /* -8..7 */
      e[63] = (sbyte)carry2; /* 0..8 */

      GeP3ToCached(ref Ai[0], A);
      for (i = 0; i < 7; i++)
      {
        GeAdd(ref t, A, Ai[i]);
        GeP1P1ToP3(ref u, t);
        GeP3ToCached(ref Ai[i + 1], u);
      }

      GeP20(ref r);
      for (i = 63; i >= 0; i--)
      {
        sbyte b = e[i];
        byte bnegative = Negative((sbyte)b);
        byte babs = (byte)(b - (((-bnegative) & b) << 1));
        GeCached cur = new GeCached();
        GeCached minuscur = new GeCached();
        GeP2Dbl(ref t, r);
        GeP1P1ToP2(ref r, t);
        GeP2Dbl(ref t, r);
        GeP1P1ToP2(ref r, t);
        GeP2Dbl(ref t, r);
        GeP1P1ToP2(ref r, t);
        GeP2Dbl(ref t, r);
        GeP1P1ToP3(ref u, t);
        GeCached0(ref cur);
        GeCachedCmov(ref cur, Ai[0], Equal((sbyte)babs, 1));
        GeCachedCmov(ref cur, Ai[1], Equal((sbyte)babs, 2));
        GeCachedCmov(ref cur, Ai[2], Equal((sbyte)babs, 3));
        GeCachedCmov(ref cur, Ai[3], Equal((sbyte)babs, 4));
        GeCachedCmov(ref cur, Ai[4], Equal((sbyte)babs, 5));
        GeCachedCmov(ref cur, Ai[5], Equal((sbyte)babs, 6));
        GeCachedCmov(ref cur, Ai[6], Equal((sbyte)babs, 7));
        GeCachedCmov(ref cur, Ai[7], Equal((sbyte)babs, 8));
        FeCopy(ref minuscur.YplusX, cur.YminusX);
        FeCopy(ref minuscur.YminusX, cur.YplusX);
        FeCopy(ref minuscur.Z, cur.Z);
        FeNeg(ref minuscur.T2d, cur.T2d);
        GeCachedCmov(ref cur, minuscur, bnegative);
        GeAdd(ref t, u, cur);
        GeP1P1ToP2(ref r, t);
      }
    }

    public static string Commit(string amount, string mask)
    {
      if (mask.Length != 64 || amount.Length != 64)
      {
        throw new Exception("invalid amount or mask!");
      }
      string C = ByteArrayToHex(NaclFastCn.GeDoubleScalarmultBaseVartime(HexToByteArray(amount), HexToByteArray(H), HexToByteArray(mask)));
      return C;
    }

    public static string D2b(string integer)
    {
      UInt64 value = Convert.ToUInt64(integer);
      string res = Convert.ToString((long)value, 2);
      string addition = new string('0', 64 - res.Length);
      return new string((addition + res).Reverse().ToArray());
    }

    public static MaskAmount EncodeRctEcdh(MaskAmount ecdh, string key)
    {
      byte[] first = HexToByteArray(HashToScalar(key));
      byte[] second = HexToByteArray(HashToScalar(ByteArrayToHex(first)));

      byte[] maskRes = new byte[32];
      byte[] amountRes = new byte[32];
      ScAdd(ref maskRes, HexToByteArray(ecdh.Mask), first);
      ScAdd(ref amountRes, HexToByteArray(ecdh.Amount), second);

      return new MaskAmount
      {
        Mask = ByteArrayToHex(maskRes),
        Amount = ByteArrayToHex(amountRes)
      };
    }

    public static string SerializeRctBase(RctSignatures rv)
    {
      string buf = "";
      buf += EncodeVarint(rv.Type);
      buf += EncodeVarint(Convert.ToInt64(rv.TxnFee));
      if (rv.Type == 2)
      {
        for (var i = 0; i < rv.PseudoOuts.Length; i++)
        {
          buf += rv.PseudoOuts[i];
        }
      }
      if (rv.EcdhInfo.Length != rv.OutPk.Length)
      {
        throw new Exception("mismatched outPk/ecdhInfo!");
      }
      for (Int32 i = 0; i < rv.EcdhInfo.Length; i++)
      {
        buf += rv.EcdhInfo[i].Mask;
        buf += rv.EcdhInfo[i].Amount;
      }
      for (Int32 i = 0; i < rv.OutPk.Length; i++)
      {
        buf += rv.OutPk[i];
      }
      return buf;
    }

    public static byte[] GetPreMlsagHash(RctSignatures rv)
    {
      string hashes = "";
      hashes += rv.Message;
      hashes += ByteArrayToHex(CnFastHash(HexToByteArray(SerializeRctBase(rv))));
      string buf = SerializeRangeProofs(rv);
      hashes += ByteArrayToHex(CnFastHash(HexToByteArray(buf)));
      return CnFastHash(HexToByteArray(hashes));
    }

    public static string SerializeRangeProofs(RctSignatures rv)
    {
      string buf = "";
      for (var i = 0; i < rv.P.RangeSigs.Length; i++)
      {
        for (var j = 0; j < rv.P.RangeSigs[i].Bsig.s.Count; j++)
        {
          for (var l = 0; l < rv.P.RangeSigs[i].Bsig.s[j].Length; l++)
          {
            buf += rv.P.RangeSigs[i].Bsig.s[j][l];
          }
        }
        buf += rv.P.RangeSigs[i].Bsig.ee;
        for (Int32 j = 0; j < rv.P.RangeSigs[i].Ci.Length; j++)
        {
          buf += rv.P.RangeSigs[i].Ci[j];
        }
      }
      return buf;
    }

    public static string ArrayHashToScalar(string[] array)
    {
      string buf = "";

      for (var i = 0; i < array.Length; i++)
      {
        buf += array[i];
      }
      return HashToScalar(buf);
    }
    public static byte[] HashToEc2(byte[] key)
    {
      GeP2 gep2 = new GeP2();
      GeP3 gep3 = new GeP3();
      GeP1P1 gep1p1 = new GeP1P1();
      byte[] hash = CnFastHash(key);
      GeFromfeFrombytesVartime(ref gep2, hash);
      GeMul8(ref gep1p1, gep2);
      GeP1P1ToP3(ref gep3, gep1p1);
      byte[] res = new byte[32];
      GeP3ToBytes(ref res, gep3);
      return res;
    }

    public static BigInteger Exp10(this BigInteger b, Int32 n)
    {
      return BigInteger.Multiply(b, BigInteger.Pow(new BigInteger(10), n));
    }

    public static void GeTobytes(ref byte[] s, GeP2 h)
    {
      Int32[] recip = new Int32[10];
      Int32[] x = new Int32[10];
      Int32[] y = new Int32[10];

      FeInvert(ref recip, h.Z);
      FeMul(ref x, h.X, recip);
      FeMul(ref y, h.Y, recip);
      FeTobytes(ref s, y);
      s[31] ^= (byte)(FeIsnegative(x) << 7);
    }
  }
}
