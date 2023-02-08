using System;
using System.Linq;
using System.Security.Cryptography;
using NBitcoin;
using CryptoUtils.CryptoNote;
using System.Numerics;
using System.Collections.Concurrent;

namespace CryptoUtils
{
  public class PrivateSession
  {
    private AesCryptoServiceProvider aes = new AesCryptoServiceProvider();

    static ConcurrentDictionary<string, byte[]> ClientCounter = new ConcurrentDictionary<string, byte[]>();

    Key _sessionKey;

    public PrivateSession(byte[] PrivateKey)
    {
      _sessionKey = new Key(PrivateKey);
    }

    public void Dispose()
    {
      aes.Dispose();
    }

    static void IncrementCounter(byte[] ClientKey, out byte[] _counter)
    {
      if (!ClientCounter.ContainsKey(ClientKey.ToHex()))
      {
        ClientCounter[ClientKey.ToHex()] = new byte[4] { 0, 0, 0, 1 };
      }

      _counter = ClientCounter[ClientKey.ToHex()];

      for (var i = _counter.Length - 1; i >= 0; i--)
      {
        if (++_counter[i] != 0)
          break;
      }
    }
    private byte[] SharedSecret(byte[] ClientKey, byte[] IndexCounter)
    {
      var derivation = ScalarKey.GenerateKeyDerivation(new Key(ClientKey), _sessionKey);
      var encoded = CryptonoteUtils.EncodeVarint(new BigInteger(IndexCounter.Reverse().ToArray()));
      var scalar1 = CryptonoteUtils.DerivationToScalar(derivation.ToHex(), encoded);
      var sha3 = Sha3Kessak(scalar1.HexToByteArray());

      using (SHA512Managed sha = new SHA512Managed())
      {
        return sha.ComputeHash(sha3);
      }
    }
    static byte[] Sha3Kessak(byte[] key)
    {
      byte[] data = new byte[38];
      Buffer.BlockCopy(System.Text.Encoding.UTF8.GetBytes("orders"), 0, data, 0, 6);
      Buffer.BlockCopy(key, 0, data, 6, key.Length);
      return CryptonoteUtils.CnFastHash(data);
    }
    public bool TryDecrypt(byte[] encrypted, out DecryptResult result)
    {

      result = new DecryptResult();

      try
      {

        var counter = encrypted.SafeSubarray(0, 4);
        var clientKey = encrypted.SafeSubarray(4, 32);
        var cipherText = encrypted.SafeSubarray(36, encrypted.Length - 32 - 36);
        var mac = encrypted.SafeSubarray(encrypted.Length - 32);

        var sharedKey = SharedSecret(clientKey, counter);

        var iv = sharedKey.SafeSubarray(0, 16);
        var encryptionKey = sharedKey.SafeSubarray(16, 16);
        var hashingKey = sharedKey.SafeSubarray(32);

        var hashMAC = new HMACSHA256(hashingKey).ComputeHash(encrypted.SafeSubarray(0, encrypted.Length - 32));

        if (!ArrayEqual(mac, hashMAC))
          throw new Exception("Invalid.");

        var unprotected = AesUnprotect(cipherText, encryptionKey, iv);
        result.ephemeralKey = clientKey;
        result.message = unprotected;

        return true;
      }
      catch
      {
        return false;
      }
    }

    public byte[] Encrypt(byte[] message, byte[] clientKey)
    {

      IncrementCounter(clientKey, out byte[] _counter);

      var sharedKey = SharedSecret(clientKey, _counter);
      var iv = sharedKey.SafeSubarray(0, 16);
      var encryptionKey = sharedKey.SafeSubarray(16, 16);
      var hashingKey = sharedKey.SafeSubarray(32);
      var cipherText = AesProtect(message, encryptionKey, iv);
      var encrypted = _counter.Concat(clientKey, cipherText);
      var hashMAC = new HMACSHA256(hashingKey).ComputeHash(encrypted);

      return encrypted.Concat(hashMAC);
    }

    byte[] AesProtect(byte[] bytes, byte[] KEY, byte[] IV)
    {
      using (var encryptorTransformer = aes.CreateEncryptor(KEY, IV))
        return encryptorTransformer.TransformFinalBlock(bytes, 0, bytes.Length);
    }

    byte[] AesUnprotect(byte[] bytes, byte[] KEY, byte[] IV)
    {
      using (var decryptorTransformer = aes.CreateDecryptor(KEY, IV))
        return decryptorTransformer.TransformFinalBlock(bytes, 0, bytes.Length);
    }

    static bool ArrayEqual(byte[] a, byte[] b)
    {
      if (a == null && b == null)
        return true;
      if (a == null)
        return false;
      if (b == null)
        return false;
      return ArrayEqual(a, 0, b, 0, Math.Max(a.Length, b.Length));
    }

    static bool ArrayEqual(byte[] a, int startA, byte[] b, int startB, int length)
    {
      if (a == null && b == null)
        return true;
      if (a == null)
        return false;
      if (b == null)
        return false;
      var alen = a.Length - startA;
      var blen = b.Length - startB;

      if (alen < length || blen < length)
        return false;

      for (int ai = startA, bi = startB; ai < startA + length; ai++, bi++)
      {
        if (a[ai] != b[bi])
          return false;
      }
      return true;
    }

  }

  public class DecryptResult
  {
    public byte[] message { get; set; }
    public byte[] ephemeralKey { get; set; }
  }
}
