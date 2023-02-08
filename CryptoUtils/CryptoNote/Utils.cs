using System;

namespace CryptoUtils.CryptoNote
{
  public static class Utils
  {
    public static T[] SubArray<T>(this T[] data, int index, int length)
    {
      T[] result = new T[length];
      Array.Copy(data, index, result, 0, length);
      return result;
    }

    public static T[] SubArray<T>(this T[] data, int index)
    {
      if (index > data.Length)
      {
        return new T[0];
      }
      T[] result = new T[data.Length - index];
      Array.Copy(data, index, result, 0, data.Length - index);
      return result;
    }
  }
}
