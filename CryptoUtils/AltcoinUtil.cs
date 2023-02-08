using NBitcoin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoUtils
{
  public class AltcoinUtil
  {
    public static Key RandomSecretKey()
    {
      return new Key();
    }
    public static Key RandomClientKey(Key test_secret)
    {
      var new_key = new Key();

      bool success = false;

      while (!success)
      {
        success = ValidScalar(new_key, test_secret);

        if (!success)
        new_key = new Key();
      }

      return new_key;
    }

    static bool ValidScalar(Key new_key, Key test_secret)
    {
      try
      {
        var derivation = ScalarKey.GenerateKeyDerivation(new_key, test_secret);
        return true;
      }
      catch (Exception)
      {
        return false;
      }
    }
    public static string DeriveAddress(string extPubKeyHex, int index, string symbol, bool segwit)
    {

      Network network = GetBLKNetworkAlt(symbol);
      ExtPubKey extPubKey = new ExtPubKey(extPubKeyHex);
      var xkey = extPubKey.Derive(index, false);

      if (segwit)
      return xkey.PubKey.Compress(true).GetSegwitAddress(network).ToString();

      return xkey.PubKey.Compress(false).GetAddress(network).ToString();
    }
    public static bool ValidAddress(string address, string symbol)
    {
      try
      {
        Network network = GetBLKNetworkAlt(symbol);
        if(address != BitcoinAddress.Create(address, network).ToString())
        return false;

        return true;
      }
      catch { return false; }
    }

    static Network GetBLKNetworkAlt(string blk)
    {
      switch (blk)
      {
        case "btc":
        return Network.Main;

        case "ltc":
        return NBitcoin.Altcoins.Litecoin.Instance.Mainnet;

        case "dash":
        return NBitcoin.Altcoins.Dash.Instance.Mainnet;

        case "dgb":
        return NBitcoin.Altcoins.DigiByte.Instance.Mainnet;

        case "doge":
        return NBitcoin.Altcoins.Dogecoin.Instance.Mainnet;

        case "grs":
        return NBitcoin.Altcoins.Groestlcoin.Instance.Mainnet;

        default:
        throw new System.Exception("invalid network type");
      }
    }

  }
}
