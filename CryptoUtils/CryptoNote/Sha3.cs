using System;

namespace CryptoUtils.CryptoNote
{
  public class Sha3
  {
    private readonly string[] HEX_CHARS = { "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f" };
    private readonly int _bits;
    private readonly int _blockCount;
    private readonly int _byteCount;
    private readonly Int32[] _padding;
    private readonly int _outputBits;
    private readonly int _outputBlocks;
    private readonly int _extraBytes;
    private readonly int[] SHIFT = { 0, 8, 16, 24 };
    private readonly UInt32[] RC = {
            1, 0, 32898, 0, 32906, 2147483648, 2147516416, 2147483648, 32907, 0, 2147483649,
            0, 2147516545, 2147483648, 32777, 2147483648, 138, 0, 136, 0, 2147516425, 0,
            2147483658, 0, 2147516555, 0, 139, 2147483648, 32905, 2147483648, 32771,
            2147483648, 32770, 2147483648, 128, 2147483648, 32778, 0, 2147483658, 2147483648,
            2147516545, 2147483648, 32896, 2147483648, 2147483649, 0, 2147516424, 2147483648
        };

    private Int32[] _blocks;
    private Int32[] _s;
    private bool _reset;
    private int _lastByteIndex;
    private int _start;
    private Int32 _block;


    public Sha3()
    {
      var bits = 256;
      var outputBits = 256;
      var padding = new Int32[] { 1, 256, 65536, 16777216 };


      _s = new Int32[50];
      _padding = padding;
      _outputBits = 0;
      _block = 0;
      _start = 0;
      _blockCount = (1600 - (bits << 1)) >> 5;
      _byteCount = _blockCount << 2;
      _outputBlocks = outputBits >> 5;
      _extraBytes = (outputBits & 31) >> 3;
      _blocks = new Int32[_blockCount + 1];
      _reset = true;

      for (var i = 0; i < 50; ++i)
      {
        _s[i] = 0;
      }
    }

    public byte[] Kessak(byte[] message)
    {
      Update(message);
      string str = CreateHex();
      byte[] ba = CryptonoteUtils.HexToByteArray(str);
      return ba;
    }

    private void F()
    {

      Int32 h, l, n, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9,
          b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16, b17,
          b18, b19, b20, b21, b22, b23, b24, b25, b26, b27, b28, b29, b30, b31, b32, b33,
          b34, b35, b36, b37, b38, b39, b40, b41, b42, b43, b44, b45, b46, b47, b48, b49;

      for (n = 0; n < 48; n += 2)
      {
        c0 = _s[0] ^ _s[10] ^ _s[20] ^ _s[30] ^ _s[40];
        c1 = _s[1] ^ _s[11] ^ _s[21] ^ _s[31] ^ _s[41];
        c2 = _s[2] ^ _s[12] ^ _s[22] ^ _s[32] ^ _s[42];
        c3 = _s[3] ^ _s[13] ^ _s[23] ^ _s[33] ^ _s[43];
        c4 = _s[4] ^ _s[14] ^ _s[24] ^ _s[34] ^ _s[44];
        c5 = _s[5] ^ _s[15] ^ _s[25] ^ _s[35] ^ _s[45];
        c6 = _s[6] ^ _s[16] ^ _s[26] ^ _s[36] ^ _s[46];
        c7 = _s[7] ^ _s[17] ^ _s[27] ^ _s[37] ^ _s[47];
        c8 = _s[8] ^ _s[18] ^ _s[28] ^ _s[38] ^ _s[48];
        c9 = _s[9] ^ _s[19] ^ _s[29] ^ _s[39] ^ _s[49];

        Int32 a32 = (Int32)(c8 ^ ((c2 << 1) | ((Int32)((UInt32)c3 >> 31))));

        h = c8 ^ ((c2 << 1) | (Int32)((UInt32)c3 >> 31));
        l = c9 ^ ((c3 << 1) | (Int32)((UInt32)c2 >> 31));
        _s[0] ^= h;
        _s[1] ^= l;
        _s[10] ^= h;
        _s[11] ^= l;
        _s[20] ^= h;
        _s[21] ^= l;
        _s[30] ^= h;
        _s[31] ^= l;
        _s[40] ^= h;
        _s[41] ^= l;
        h = c0 ^ ((c4 << 1) | (Int32)((UInt32)c5 >> 31));
        l = c1 ^ ((c5 << 1) | (Int32)((UInt32)c4 >> 31));
        _s[2] ^= h;
        _s[3] ^= l;
        _s[12] ^= h;
        _s[13] ^= l;
        _s[22] ^= h;
        _s[23] ^= l;
        _s[32] ^= h;
        _s[33] ^= l;
        _s[42] ^= h;
        _s[43] ^= l;
        h = c2 ^ ((c6 << 1) | (Int32)((UInt32)c7 >> 31));
        l = c3 ^ ((c7 << 1) | (Int32)((UInt32)c6 >> 31));
        _s[4] ^= h;
        _s[5] ^= l;
        _s[14] ^= h;
        _s[15] ^= l;
        _s[24] ^= h;
        _s[25] ^= l;
        _s[34] ^= h;
        _s[35] ^= l;
        _s[44] ^= h;
        _s[45] ^= l;
        h = c4 ^ ((c8 << 1) | (Int32)((UInt32)c9 >> 31));
        l = c5 ^ ((c9 << 1) | (Int32)((UInt32)c8 >> 31));
        _s[6] ^= h;
        _s[7] ^= l;
        _s[16] ^= h;
        _s[17] ^= l;
        _s[26] ^= h;
        _s[27] ^= l;
        _s[36] ^= h;
        _s[37] ^= l;
        _s[46] ^= h;
        _s[47] ^= l;
        h = c6 ^ ((c0 << 1) | (Int32)((UInt32)c1 >> 31));
        l = c7 ^ ((c1 << 1) | (Int32)((UInt32)c0 >> 31));
        _s[8] ^= h;
        _s[9] ^= l;
        _s[18] ^= h;
        _s[19] ^= l;
        _s[28] ^= h;
        _s[29] ^= l;
        _s[38] ^= h;
        _s[39] ^= l;
        _s[48] ^= h;
        _s[49] ^= l;

        b0 = _s[0];
        b1 = _s[1];
        b32 = (_s[11] << 4) | (Int32)((UInt32)_s[10] >> 28);
        b33 = (_s[10] << 4) | (Int32)((UInt32)_s[11] >> 28);
        b14 = (_s[20] << 3) | (Int32)((UInt32)_s[21] >> 29);
        b15 = (_s[21] << 3) | (Int32)((UInt32)_s[20] >> 29);
        b46 = (_s[31] << 9) | (Int32)((UInt32)_s[30] >> 23);
        b47 = (_s[30] << 9) | (Int32)((UInt32)_s[31] >> 23);
        b28 = (_s[40] << 18) | (Int32)((UInt32)_s[41] >> 14);
        b29 = (_s[41] << 18) | (Int32)((UInt32)_s[40] >> 14);
        b20 = (_s[2] << 1) | (Int32)((UInt32)_s[3] >> 31);
        b21 = (_s[3] << 1) | (Int32)((UInt32)_s[2] >> 31);
        b2 = (_s[13] << 12) | (Int32)((UInt32)_s[12] >> 20);
        b3 = (_s[12] << 12) | (Int32)((UInt32)_s[13] >> 20);
        b34 = (_s[22] << 10) | (Int32)((UInt32)_s[23] >> 22);
        b35 = (_s[23] << 10) | (Int32)((UInt32)_s[22] >> 22);
        b16 = (_s[33] << 13) | (Int32)((UInt32)_s[32] >> 19);
        b17 = (_s[32] << 13) | (Int32)((UInt32)_s[33] >> 19);
        b48 = (_s[42] << 2) | (Int32)((UInt32)_s[43] >> 30);
        b49 = (_s[43] << 2) | (Int32)((UInt32)_s[42] >> 30);
        b40 = (_s[5] << 30) | (Int32)((UInt32)_s[4] >> 2);
        b41 = (_s[4] << 30) | (Int32)((UInt32)_s[5] >> 2);
        b22 = (_s[14] << 6) | (Int32)((UInt32)_s[15] >> 26);
        b23 = (_s[15] << 6) | (Int32)((UInt32)_s[14] >> 26);
        b4 = (_s[25] << 11) | (Int32)((UInt32)_s[24] >> 21);
        b5 = (_s[24] << 11) | (Int32)((UInt32)_s[25] >> 21);
        b36 = (_s[34] << 15) | (Int32)((UInt32)_s[35] >> 17);
        b37 = (_s[35] << 15) | (Int32)((UInt32)_s[34] >> 17);
        b18 = (_s[45] << 29) | (Int32)((UInt32)_s[44] >> 3);
        b19 = (_s[44] << 29) | (Int32)((UInt32)_s[45] >> 3);
        b10 = (_s[6] << 28) | (Int32)((UInt32)_s[7] >> 4);
        b11 = (_s[7] << 28) | (Int32)((UInt32)_s[6] >> 4);
        b42 = (_s[17] << 23) | (Int32)((UInt32)_s[16] >> 9);
        b43 = (_s[16] << 23) | (Int32)((UInt32)_s[17] >> 9);
        b24 = (_s[26] << 25) | (Int32)((UInt32)_s[27] >> 7);
        b25 = (_s[27] << 25) | (Int32)((UInt32)_s[26] >> 7);
        b6 = (_s[36] << 21) | (Int32)((UInt32)_s[37] >> 11);
        b7 = (_s[37] << 21) | (Int32)((UInt32)_s[36] >> 11);
        b38 = (_s[47] << 24) | (Int32)((UInt32)_s[46] >> 8);
        b39 = (_s[46] << 24) | (Int32)((UInt32)_s[47] >> 8);
        b30 = (_s[8] << 27) | (Int32)((UInt32)_s[9] >> 5);
        b31 = (_s[9] << 27) | (Int32)((UInt32)_s[8] >> 5);
        b12 = (_s[18] << 20) | (Int32)((UInt32)_s[19] >> 12);
        b13 = (_s[19] << 20) | (Int32)((UInt32)_s[18] >> 12);
        b44 = (_s[29] << 7) | (Int32)((UInt32)_s[28] >> 25);
        b45 = (_s[28] << 7) | (Int32)((UInt32)_s[29] >> 25);
        b26 = (_s[38] << 8) | (Int32)((UInt32)_s[39] >> 24);
        b27 = (_s[39] << 8) | (Int32)((UInt32)_s[38] >> 24);
        b8 = (_s[48] << 14) | (Int32)((UInt32)_s[49] >> 18);
        b9 = (_s[49] << 14) | (Int32)((UInt32)_s[48] >> 18);

        _s[0] = b0 ^ (~b2 & b4);
        _s[1] = b1 ^ (~b3 & b5);
        _s[10] = b10 ^ (~b12 & b14);
        _s[11] = b11 ^ (~b13 & b15);
        _s[20] = b20 ^ (~b22 & b24);
        _s[21] = b21 ^ (~b23 & b25);
        _s[30] = b30 ^ (~b32 & b34);
        _s[31] = b31 ^ (~b33 & b35);
        _s[40] = b40 ^ (~b42 & b44);
        _s[41] = b41 ^ (~b43 & b45);
        _s[2] = b2 ^ (~b4 & b6);
        _s[3] = b3 ^ (~b5 & b7);
        _s[12] = b12 ^ (~b14 & b16);
        _s[13] = b13 ^ (~b15 & b17);
        _s[22] = b22 ^ (~b24 & b26);
        _s[23] = b23 ^ (~b25 & b27);
        _s[32] = b32 ^ (~b34 & b36);
        _s[33] = b33 ^ (~b35 & b37);
        _s[42] = b42 ^ (~b44 & b46);
        _s[43] = b43 ^ (~b45 & b47);
        _s[4] = b4 ^ (~b6 & b8);
        _s[5] = b5 ^ (~b7 & b9);
        _s[14] = b14 ^ (~b16 & b18);
        _s[15] = b15 ^ (~b17 & b19);
        _s[24] = b24 ^ (~b26 & b28);
        _s[25] = b25 ^ (~b27 & b29);
        _s[34] = b34 ^ (~b36 & b38);
        _s[35] = b35 ^ (~b37 & b39);
        _s[44] = b44 ^ (~b46 & b48);
        _s[45] = b45 ^ (~b47 & b49);
        _s[6] = b6 ^ (~b8 & b0);
        _s[7] = b7 ^ (~b9 & b1);
        _s[16] = b16 ^ (~b18 & b10);
        _s[17] = b17 ^ (~b19 & b11);
        _s[26] = b26 ^ (~b28 & b20);
        _s[27] = b27 ^ (~b29 & b21);
        _s[36] = b36 ^ (~b38 & b30);
        _s[37] = b37 ^ (~b39 & b31);
        _s[46] = b46 ^ (~b48 & b40);
        _s[47] = b47 ^ (~b49 & b41);
        _s[8] = b8 ^ (~b0 & b2);
        _s[9] = b9 ^ (~b1 & b3);
        _s[18] = b18 ^ (~b10 & b12);
        _s[19] = b19 ^ (~b11 & b13);
        _s[28] = b28 ^ (~b20 & b22);
        _s[29] = b29 ^ (~b21 & b23);
        _s[38] = b38 ^ (~b30 & b32);
        _s[39] = b39 ^ (~b31 & b33);
        _s[48] = b48 ^ (~b40 & b42);
        _s[49] = b49 ^ (~b41 & b43);

        _s[0] ^= (Int32)RC[n];
        _s[1] ^= (Int32)RC[n + 1];
      }
    }

    private void Final()
    {
      int i = _lastByteIndex;
      _blocks[i >> 2] |= _padding[i & 3];
      if (_lastByteIndex == _byteCount)
      {
        _blocks[0] = _blocks[_blockCount];
        for (i = 1; i < _blockCount + 1; ++i)
        {
          _blocks[i] = 0;
        }
      }
      UInt32 tmp = 0x80000000;
      _blocks[_blockCount - 1] |= (Int32)tmp;
      for (i = 0; i < _blockCount; ++i)
      {
        _s[i] ^= _blocks[i];
      }
      F();
    }

    private string CreateHex()
    {
      Final();

      int i = 0;
      int j = 0;

      string hex = "";
      Int32 block;
      while (j < _outputBlocks)
      {
        for (i = 0; i < _blockCount && j < _outputBlocks; ++i, ++j)
        {
          block = _s[i];
          hex += HEX_CHARS[(block >> 4) & 0x0F] + HEX_CHARS[block & 0x0F] +
                 HEX_CHARS[(block >> 12) & 0x0F] + HEX_CHARS[(block >> 8) & 0x0F] +
                 HEX_CHARS[(block >> 20) & 0x0F] + HEX_CHARS[(block >> 16) & 0x0F] +
                 HEX_CHARS[(block >> 28) & 0x0F] + HEX_CHARS[(block >> 24) & 0x0F];
        }
        if (j % _blockCount == 0)
        {
          F();
        }
      }
      if (_extraBytes != 0)
      {
        block = _s[i];
        if (_extraBytes > 0)
        {
          hex += HEX_CHARS[(block >> 4) & 0x0F] + HEX_CHARS[block & 0x0F];
        }
        if (_extraBytes > 1)
        {
          hex += HEX_CHARS[(block >> 12) & 0x0F] + HEX_CHARS[(block >> 8) & 0x0F];
        }
        if (_extraBytes > 2)
        {
          hex += HEX_CHARS[(block >> 20) & 0x0F] + HEX_CHARS[(block >> 16) & 0x0F];
        }
      }
      return hex;
    }

    public void Update(byte[] message)
    {
      int length = message.Length;
      int index = 0;
      int i = 0;

      while (index < length)
      {
        if (_reset)
        {
          _reset = false;
          _blocks[0] = _block;
          for (i = 1; i < _blockCount + 1; ++i)
          {
            _blocks[i] = 0;
          }
        }
        for (i = _start; index < length && i < _byteCount; ++index)
        {
          _blocks[i >> 2] |= (Int32)(message[index] << SHIFT[i++ & 3]);
        }
        _lastByteIndex = i;
        if (i >= _byteCount)
        {
          _start = i - _byteCount;
          _block = _blocks[_blockCount];
          for (i = 0; i < _blockCount; ++i)
          {
            _s[i] ^= _blocks[i];
          }
          F();
          _reset = true;
        }
        else
        {
          _start = i;
        }
      }
    }
  }
}
