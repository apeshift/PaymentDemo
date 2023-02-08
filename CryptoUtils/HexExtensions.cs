using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;

namespace CryptoUtils
{

  public static class HexExtensions
  {
    public static string ToB64(this string value)
    {
      byte[] bytes = Encoding.UTF8.GetBytes(value);
      return Convert.ToBase64String(bytes);
    }
    public static string FromB64(this string value)
    {
      byte[] bytes = Convert.FromBase64String(value);
      return Encoding.UTF8.GetString(bytes);
    }
    public static string ToHex(this byte[] value, bool prefix = false)
    {
      var strPrex = prefix ? "0x" : "";
      return strPrex + string.Concat(value.Select(b =>
      b.ToString("x2")).ToArray());
    }

    private static readonly byte[] Empty = new byte[0];
    public static byte[] HexToByteArray(this string value)
    {
      byte[] bytes = null;
      if (string.IsNullOrEmpty(value))
      {
        bytes = Empty;
      }
      else
      {
        var string_length = value.Length;
        var character_index = value.StartsWith("0x", StringComparison.Ordinal) ? 2 : 0;
        var number_of_characters = string_length - character_index;

        var add_leading_zero = false;
        if (0 != number_of_characters % 2)
        {
          add_leading_zero = true;

          number_of_characters += 1;
        }

        bytes = new byte[number_of_characters / 2];

        var write_index = 0;
        if (add_leading_zero)
        {
          bytes[write_index++] = FromCharacterToByte(value[character_index], character_index);
          character_index += 1;
        }

        for (var read_index = character_index; read_index < value.Length; read_index += 2)
        {
          var upper = FromCharacterToByte(value[read_index], read_index, 4);
          var lower = FromCharacterToByte(value[read_index + 1], read_index + 1);

          bytes[write_index++] = (byte)(upper | lower);
        }
      }

      return bytes;
    }
    private static byte FromCharacterToByte(char character, int index, int shift = 0)
    {
      var value = (byte)character;
      if (0x40 < value && 0x47 > value || 0x60 < value && 0x67 > value)
      {
        if (0x40 == (0x40 & value))
          if (0x20 == (0x20 & value))
            value = (byte)((value + 0xA - 0x61) << shift);
          else
            value = (byte)((value + 0xA - 0x41) << shift);
      }
      else if (0x29 < value && 0x40 > value)
      {
        value = (byte)((value - 0x30) << shift);
      }
      else
      {
        throw new Exception("Invalid.");
      }

      return value;
    }

  }

  public static class ByteArrayExtensions
  {
    public static bool StartWith(this byte[] data, byte[] versionBytes)
    {
      if (data.Length < versionBytes.Length)
        return false;
      for (int i = 0; i < versionBytes.Length; i++)
      {
        if (data[i] != versionBytes[i])
          return false;
      }
      return true;
    }
    public static byte[] SafeSubarray(this byte[] array, int offset, int count)
    {
      if (array == null)
        throw new ArgumentNullException(nameof(array));
      if (offset < 0 || offset > array.Length)
        throw new ArgumentOutOfRangeException("offset");
      if (count < 0 || offset + count > array.Length)
        throw new ArgumentOutOfRangeException("count");
      if (offset == 0 && array.Length == count)
        return array;
      var data = new byte[count];
      Buffer.BlockCopy(array, offset, data, 0, count);
      return data;
    }
    public static byte[] SafeSubarray(this byte[] array, int offset)
    {
      if (array == null)
        throw new ArgumentNullException(nameof(array));
      if (offset < 0 || offset > array.Length)
        throw new ArgumentOutOfRangeException("offset");

      var count = array.Length - offset;
      var data = new byte[count];
      Buffer.BlockCopy(array, offset, data, 0, count);
      return data;
    }
    public static byte[] Concat(this byte[] arr, params byte[][] arrs)
    {
      var len = arr.Length + arrs.Sum(a => a.Length);
      var ret = new byte[len];
      Buffer.BlockCopy(arr, 0, ret, 0, arr.Length);
      var pos = arr.Length;
      foreach (var a in arrs)
      {
        Buffer.BlockCopy(a, 0, ret, pos, a.Length);
        pos += a.Length;
      }
      return ret;
    }

  }
}