using System;
using System.Threading.Tasks;

namespace CryptoUtils.CryptoNote
{
  //https://github.com/pts/pts-dropbear/blob/master/ed25519_crypto.c
  public class NaclFastCn
  {
    private static readonly Int64[] gf1 = Gf(
        new Int64[] { 0x0001 }
    );
    private static readonly Int64[] X = Gf(
        new Int64[] {
                0xd51a, 0x8f25, 0x2d60, 0xc956,
                0xa7b2, 0x9525, 0xc760, 0x692c,
                0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
                0x53fe, 0xcd6e, 0x36d3, 0x2169
        }
    );
    private static readonly Int64[] Y = Gf(
        new Int64[] {
                0x6658, 0x6666, 0x6666, 0x6666,
                0x6666, 0x6666, 0x6666, 0x6666,
                0x6666, 0x6666, 0x6666, 0x6666,
                0x6666, 0x6666, 0x6666, 0x6666
        }
    );
    public static readonly Int64[] D2 = Gf(
        new Int64[] {
                0xf159, 0x26b2, 0x9b94, 0xebd6,
                0xb156, 0x8283, 0x149a, 0x00e0,
                0xd130, 0xeef3, 0x80f2, 0x198e,
                0xfce7, 0x56df, 0xd9dc, 0x2406
        }
    );
    public static readonly Int64[] I = Gf(
        new Int64[] {
                0xa0b0, 0x4a0e, 0x1b27, 0xc4ee,
                0xe478, 0xad2f, 0x1806, 0x2f43,
                0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
                0xdf0b, 0x4fc1, 0x2480, 0x2b83
        }
    );
    public static readonly Int64[] D = Gf(
        new Int64[] {
                0x78a3, 0x1359, 0x4dca, 0x75eb,
                0xd8ab, 0x4141, 0x0a4d, 0x0070,
                0xe898, 0x7779, 0x4079, 0x8cc7,
                0xfe73, 0x2b6f, 0x6cee, 0x5203
        }
    );

    private static void S(ref Int64[] o, Int64[] a)
    {
      M(ref o, ref a, ref a);
    }

    private static void Inv25519(ref Int64[] o, Int64[] i)
    {
      Int64[] c = Gf();

      for (var j = 0; j < 16; j++)
      {
        c[j] = i[j];
      }

      for (var j = 253; j >= 0; j--)
      {
        S(ref c, c);
        if (j != 2 && j != 4)
        {
          M(ref c, ref c, ref i);
        }
      }

      for (var j = 0; j < 16; j++)
      {
        o[j] = c[j];
      }
    }

    private static void Car25519(ref Int64[] o)
    {
      var c = 1;
      for (var i = 0; i < 16; i++)
      {
        var v = o[i] + c + 65535;
        c = (Int32)Math.Floor(v / (double)65536);
        o[i] = v - c * 65536;
      }
      o[0] += c - 1 + 37 * (c - 1);
    }

    private static void Pack25519(ref byte[] o, Int64[] n)
    {
      Int64[] m = Gf(), t = Gf();
      for (var i = 0; i < 16; i++)
      {
        t[i] = n[i];
      }

      Car25519(ref t);
      Car25519(ref t);
      Car25519(ref t);

      for (var j = 0; j < 2; j++)
      {
        m[0] = t[0] - 0xffed;
        for (var i = 1; i < 15; i++)
        {
          m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
          m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        var b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        Sel25519(ref t, ref m, (byte)(1 - b));
      }

      for (var i = 0; i < 16; i++)
      {
        o[2 * i] = (byte)(t[i] & 0xff);
        o[2 * i + 1] = (byte)(t[i] >> 8);
      }
    }

    private static byte Par25519(Int64[] a)
    {
      byte[] d = new byte[32];
      Pack25519(ref d, a);
      return (byte)(d[0] & 1);
    }

    private static void Pack(ref byte[] r, Int64[][] p)
    {
      Int64[] Tx = Gf();
      Int64[] ty = Gf();
      Int64[] zi = Gf();
      Inv25519(ref zi, p[2]);
      M(ref Tx, ref p[0], ref zi);
      M(ref ty, ref p[1], ref zi);
      Pack25519(ref r, ty);
      r[31] ^= (byte)(Par25519(Tx) << 7);
    }

    public static byte[] GeScalarmultBase(byte[] key)
    {
      Int64[][] p = { Gf(), Gf(), Gf(), Gf() };
      Scalarbase(ref p, key);
      byte[] pk = new byte[key.Length];
      Pack(ref pk, p);
      return pk;

    }

    private static void Set25519(ref Int64[] r, Int64[] a)
    {
      for (var i = 0; i < 16; ++i)
      {
        r[i] = a[i];
      }
    }

    private static void Scalarbase(ref Int64[][] p, byte[] s)
    {
      Int64[][] q = { Gf(), Gf(), Gf(), Gf() };

      Set25519(ref q[0], X);
      Set25519(ref q[1], Y);
      Set25519(ref q[2], gf1);
      var x = X;
      var y = Y;
      M(ref q[3], ref x, ref y);
      Scalarmult(ref p, ref q, ref s);
    }

    private static void Sel25519(ref Int64[] p, ref Int64[] q, byte b)
    {
      Int64 c = (Int64)(~(b - 1));
      Int64 t;
      for (var i = 0; i < 16; i++)
      {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
      }
    }

    private static void Cswap(ref Int64[][] p, ref Int64[][] q, byte b)
    {
      for (Int32 i = 0; i < 4; i++)
      {
        Sel25519(ref p[i], ref q[i], b);
      }
    }

    private static void Add(ref Int64[][] p, ref Int64[][] q)
    {
      Int64[] a = Gf(), b = Gf(), c = Gf(),
          d = Gf(), e = Gf(), f = Gf(),
          g = Gf(), h = Gf(), t = Gf();

      Z(ref a, ref p[1], ref p[0]);
      Z(ref t, ref q[1], ref q[0]);
      M(ref a, ref a, ref t);
      A(ref b, ref p[0], ref p[1]);
      A(ref t, ref q[0], ref q[1]);
      M(ref b, ref b, ref t);
      M(ref c, ref p[3], ref q[3]);
      var d2 = D2;
      M(ref c, ref c, ref d2);
      M(ref d, ref p[2], ref q[2]);
      A(ref d, ref d, ref d);
      Z(ref e, ref b, ref a);
      Z(ref f, ref d, ref c);
      A(ref g, ref d, ref c);
      A(ref h, ref b, ref a);


      M(ref p[0], ref e, ref f);
      M(ref p[1], ref h, ref g);
      M(ref p[2], ref g, ref f);
      M(ref p[3], ref e, ref h);
    }

    private static Int64[] ToSingle(Int64[][] p)
    {
      Int64[] res = new Int64[4 * 16];
      for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 16; ++j)
          res[i * 16 + j] = p[i][j];
      return res;
    }

    private static void ToDouble(Int64[] p, Int64[][] res)
    {
      for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 16; ++j)
          res[i][j] = p[i * 16 + j];
    }

    public static bool Comp(Int64[][] a, Int64[][] b)
    {
      for (int i = 0; i < a.Length; ++i)
        for (int j = 0; j < b.Length; ++j)
          if (a[i][j] != b[i][j])
            return false;
      return true;
    }

    public static void Scalarmult(ref Int64[][] p, ref Int64[][] q, ref byte[] s)
    {
      byte b;
      Set25519(ref p[0], Gf());
      Set25519(ref p[1], gf1);
      Set25519(ref p[2], gf1);
      Set25519(ref p[3], Gf());
      for (int i = 255; i >= 0; --i)
      {
        b = (byte)((s[(i / 8) | 0] >> (i & 7)) & 1);
        Cswap(ref p, ref q, b);
        Add(ref q, ref p);
        Add(ref p, ref p);
        Cswap(ref p, ref q, b);
      }

    }

    public static void Z(ref Int64[] o, ref Int64[] a, ref Int64[] b)
    {
      for (var i = 0; i < 16; i++)
      {
        o[i] = a[i] - b[i];
      }
    }

    public static void A(ref Int64[] o, ref Int64[] a, ref Int64[] b)
    {
      for (var i = 0; i < 16; i++)
      {
        o[i] = a[i] + b[i];
      }
    }

    public static void M(ref Int64[] o, ref Int64[] a, ref Int64[] b)
    {
      Int64 v, c,
          b0 = b[0], b1 = b[1], b2 = b[2], b3 = b[3], b4 = b[4], b5 = b[5],
          b6 = b[6], b7 = b[7], b8 = b[8], b9 = b[9], b10 = b[10],
          b11 = b[11], b12 = b[12], b13 = b[13], b14 = b[14], b15 = b[15];

      v = a[0];
      Int64
          t0 = v * b0, t1 = v * b1, t2 = v * b2, t3 = v * b3,
          t4 = v * b4, t5 = v * b5, t6 = v * b6, t7 = v * b7,
          t8 = v * b8, t9 = v * b9, t10 = v * b10, t11 = v * b11,
          t12 = v * b12, t13 = v * b13, t14 = v * b14, t15 = v * b15;

      v = a[1];
      t1 += v * b0; t2 += v * b1; t3 += v * b2; t4 += v * b3;
      t5 += v * b4; t6 += v * b5; t7 += v * b6; t8 += v * b7;
      t9 += v * b8; t10 += v * b9; t11 += v * b10; t12 += v * b11;
      t13 += v * b12; t14 += v * b13; t15 += v * b14;
      Int64 t16 = v * b15;

      v = a[2];
      t2 += v * b0; t3 += v * b1; t4 += v * b2; t5 += v * b3;
      t6 += v * b4; t7 += v * b5; t8 += v * b6; t9 += v * b7;
      t10 += v * b8; t11 += v * b9; t12 += v * b10; t13 += v * b11;
      t14 += v * b12; t15 += v * b13; t16 += v * b14;
      Int64 t17 = v * b15;

      v = a[3];
      t3 += v * b0; t4 += v * b1; t5 += v * b2; t6 += v * b3;
      t7 += v * b4; t8 += v * b5; t9 += v * b6; t10 += v * b7;
      t11 += v * b8; t12 += v * b9; t13 += v * b10; t14 += v * b11;
      t15 += v * b12; t16 += v * b13; t17 += v * b14;
      Int64 t18 = v * b15;

      v = a[4];
      t4 += v * b0; t5 += v * b1; t6 += v * b2; t7 += v * b3;
      t8 += v * b4; t9 += v * b5; t10 += v * b6; t11 += v * b7;
      t12 += v * b8; t13 += v * b9; t14 += v * b10; t15 += v * b11;
      t16 += v * b12; t17 += v * b13; t18 += v * b14;
      Int64 t19 = v * b15;

      v = a[5];
      t5 += v * b0; t6 += v * b1; t7 += v * b2; t8 += v * b3;
      t9 += v * b4; t10 += v * b5; t11 += v * b6; t12 += v * b7;
      t13 += v * b8; t14 += v * b9; t15 += v * b10; t16 += v * b11;
      t17 += v * b12; t18 += v * b13; t19 += v * b14;
      Int64 t20 = v * b15;

      v = a[6];
      t6 += v * b0; t7 += v * b1; t8 += v * b2; t9 += v * b3;
      t10 += v * b4; t11 += v * b5; t12 += v * b6; t13 += v * b7;
      t14 += v * b8; t15 += v * b9; t16 += v * b10; t17 += v * b11;
      t18 += v * b12; t19 += v * b13; t20 += v * b14;
      Int64 t21 = v * b15;

      v = a[7];
      t7 += v * b0; t8 += v * b1; t9 += v * b2; t10 += v * b3;
      t11 += v * b4; t12 += v * b5; t13 += v * b6; t14 += v * b7;
      t15 += v * b8; t16 += v * b9; t17 += v * b10; t18 += v * b11;
      t19 += v * b12; t20 += v * b13; t21 += v * b14;
      Int64 t22 = v * b15;

      v = a[8];
      t8 += v * b0; t9 += v * b1; t10 += v * b2; t11 += v * b3;
      t12 += v * b4; t13 += v * b5; t14 += v * b6; t15 += v * b7;
      t16 += v * b8; t17 += v * b9; t18 += v * b10; t19 += v * b11;
      t20 += v * b12; t21 += v * b13; t22 += v * b14;
      Int64 t23 = v * b15;

      v = a[9];
      t9 += v * b0; t10 += v * b1; t11 += v * b2; t12 += v * b3;
      t13 += v * b4; t14 += v * b5; t15 += v * b6; t16 += v * b7;
      t17 += v * b8; t18 += v * b9; t19 += v * b10; t20 += v * b11;
      t21 += v * b12; t22 += v * b13; t23 += v * b14;
      Int64 t24 = v * b15;

      v = a[10];
      t10 += v * b0; t11 += v * b1; t12 += v * b2; t13 += v * b3;
      t14 += v * b4; t15 += v * b5; t16 += v * b6; t17 += v * b7;
      t18 += v * b8; t19 += v * b9; t20 += v * b10; t21 += v * b11;
      t22 += v * b12; t23 += v * b13; t24 += v * b14;
      Int64 t25 = v * b15;

      v = a[11];
      t11 += v * b0; t12 += v * b1; t13 += v * b2; t14 += v * b3;
      t15 += v * b4; t16 += v * b5; t17 += v * b6; t18 += v * b7;
      t19 += v * b8; t20 += v * b9; t21 += v * b10; t22 += v * b11;
      t23 += v * b12; t24 += v * b13; t25 += v * b14;
      Int64 t26 = v * b15;

      v = a[12];
      t12 += v * b0; t13 += v * b1; t14 += v * b2; t15 += v * b3;
      t16 += v * b4; t17 += v * b5; t18 += v * b6; t19 += v * b7;
      t20 += v * b8; t21 += v * b9; t22 += v * b10; t23 += v * b11;
      t24 += v * b12; t25 += v * b13; t26 += v * b14;
      Int64 t27 = v * b15;

      v = a[13];
      t13 += v * b0; t14 += v * b1; t15 += v * b2; t16 += v * b3;
      t17 += v * b4; t18 += v * b5; t19 += v * b6; t20 += v * b7;
      t21 += v * b8; t22 += v * b9; t23 += v * b10; t24 += v * b11;
      t25 += v * b12; t26 += v * b13; t27 += v * b14;
      Int64 t28 = v * b15;

      v = a[14];
      t14 += v * b0; t15 += v * b1; t16 += v * b2; t17 += v * b3;
      t18 += v * b4; t19 += v * b5; t20 += v * b6; t21 += v * b7;
      t22 += v * b8; t23 += v * b9; t24 += v * b10; t25 += v * b11;
      t26 += v * b12; t27 += v * b13; t28 += v * b14;
      Int64 t29 = v * b15;

      v = a[15];
      t15 += v * b0; t16 += v * b1; t17 += v * b2; t18 += v * b3;
      t19 += v * b4; t20 += v * b5; t21 += v * b6; t22 += v * b7;
      t23 += v * b8; t24 += v * b9; t25 += v * b10; t26 += v * b11;
      t27 += v * b12; t28 += v * b13; t29 += v * b14;
      Int64 t30 = v * b15;

      t0 += (t16 << 1) + (t16 << 2) + (t16 << 5);
      t1 += (t17 << 1) + (t17 << 2) + (t17 << 5);
      t2 += (t18 << 1) + (t18 << 2) + (t18 << 5);
      t3 += (t19 << 1) + (t19 << 2) + (t19 << 5);
      t4 += (t20 << 1) + (t20 << 2) + (t20 << 5);
      t5 += (t21 << 1) + (t21 << 2) + (t21 << 5);
      t6 += (t22 << 1) + (t22 << 2) + (t22 << 5);
      t7 += (t23 << 1) + (t23 << 2) + (t23 << 5);
      t8 += (t24 << 1) + (t24 << 2) + (t24 << 5);
      t9 += (t25 << 1) + (t25 << 2) + (t25 << 5);
      t10 += (t26 << 1) + (t26 << 2) + (t26 << 5);
      t11 += (t27 << 1) + (t27 << 2) + (t27 << 5);
      t12 += (t28 << 1) + (t28 << 2) + (t28 << 5);
      t13 += (t29 << 1) + (t29 << 2) + (t29 << 5);
      t14 += (t30 << 1) + (t30 << 2) + (t30 << 5);

      // first car
      c = 1;
      v = t0 + c + 0x00FFFF; c = v >> 16; t0 = v - (c << 16);
      v = t1 + c + 0x00FFFF; c = v >> 16; t1 = v - (c << 16);
      v = t2 + c + 0x00FFFF; c = v >> 16; t2 = v - (c << 16);
      v = t3 + c + 0x00FFFF; c = v >> 16; t3 = v - (c << 16);
      v = t4 + c + 0x00FFFF; c = v >> 16; t4 = v - (c << 16);
      v = t5 + c + 0x00FFFF; c = v >> 16; t5 = v - (c << 16);
      v = t6 + c + 0x00FFFF; c = v >> 16; t6 = v - (c << 16);
      v = t7 + c + 0x00FFFF; c = v >> 16; t7 = v - (c << 16);
      v = t8 + c + 0x00FFFF; c = v >> 16; t8 = v - (c << 16);
      v = t9 + c + 0x00FFFF; c = v >> 16; t9 = v - (c << 16);
      v = t10 + c + 0x00FFFF; c = v >> 16; t10 = v - (c << 16);
      v = t11 + c + 0x00FFFF; c = v >> 16; t11 = v - (c << 16);
      v = t12 + c + 0x00FFFF; c = v >> 16; t12 = v - (c << 16);
      v = t13 + c + 0x00FFFF; c = v >> 16; t13 = v - (c << 16);
      v = t14 + c + 0x00FFFF; c = v >> 16; t14 = v - (c << 16);
      v = t15 + c + 0x00FFFF; c = v >> 16; t15 = v - (c << 16);
      t0 += (c << 1) + (c << 2) + (c << 5) - 38;

      // second car
      c = 1;
      v = t0 + c + 0x00FFFF; c = v >> 16; t0 = v - (c << 16);
      v = t1 + c + 0x00FFFF; c = v >> 16; t1 = v - (c << 16);
      v = t2 + c + 0x00FFFF; c = v >> 16; t2 = v - (c << 16);
      v = t3 + c + 0x00FFFF; c = v >> 16; t3 = v - (c << 16);
      v = t4 + c + 0x00FFFF; c = v >> 16; t4 = v - (c << 16);
      v = t5 + c + 0x00FFFF; c = v >> 16; t5 = v - (c << 16);
      v = t6 + c + 0x00FFFF; c = v >> 16; t6 = v - (c << 16);
      v = t7 + c + 0x00FFFF; c = v >> 16; t7 = v - (c << 16);
      v = t8 + c + 0x00FFFF; c = v >> 16; t8 = v - (c << 16);
      v = t9 + c + 0x00FFFF; c = v >> 16; t9 = v - (c << 16);
      v = t10 + c + 0x00FFFF; c = v >> 16; t10 = v - (c << 16);
      v = t11 + c + 0x00FFFF; c = v >> 16; t11 = v - (c << 16);
      v = t12 + c + 0x00FFFF; c = v >> 16; t12 = v - (c << 16);
      v = t13 + c + 0x00FFFF; c = v >> 16; t13 = v - (c << 16);
      v = t14 + c + 0x00FFFF; c = v >> 16; t14 = v - (c << 16);
      v = t15 + c + 0x00FFFF; c = v >> 16; t15 = v - (c << 16);
      t0 += (c << 1) + (c << 2) + (c << 5) - 38;

      o[0] = t0;
      o[1] = t1;
      o[2] = t2;
      o[3] = t3;
      o[4] = t4;
      o[5] = t5;
      o[6] = t6;
      o[7] = t7;
      o[8] = t8;
      o[9] = t9;
      o[10] = t10;
      o[11] = t11;
      o[12] = t12;
      o[13] = t13;
      o[14] = t14;
      o[15] = t15;

    }

    private static void Pow2523(ref Int64[] o, ref Int64[] i)
    {
      Int64[] c = Gf();

      for (Int64 a = 0; a < 16; a++)
      {
        c[a] = i[a];
      }

      for (Int32 a = 250; a >= 0; a--)
      {
        S(ref c, c);
        if (a != 1)
        {
          M(ref c, ref c, ref i);
        }
      }
      for (Int32 a = 0; a < 16; a++)
      {
        o[a] = c[a];
      }

    }

    private static void Unpack25519(ref Int64[] o, byte[] n)
    {
      for (Int64 i = 0; i < 16; i++)
      {
        o[i] = n[2 * i] + (n[2 * i + 1] << 8);
      }

      o[15] &= 0x7fff;
    }

    private static Int32 Vn(byte[] x, Int32 xi, byte[] y, Int32 yi, Int32 n)
    {
      Int32 d = 0;
      for (Int32 i = 0; i < n; i++)
      {
        d |= x[xi + i] ^ y[yi + i];
      }

      return (1 & (Int32)((UInt32)(d - 1) >> 8)) - 1;
    }

    private static Int32 CryptoVerify32(byte[] x, Int32 xi, byte[] y, Int32 yi)
    {
      return Vn(x, xi, y, yi, 32);
    }

    private static Int32 Neq25519(Int64[] a, Int64[] b)
    {
      byte[] c = new byte[32];
      byte[] d = new byte[32];

      Pack25519(ref c, a);
      Pack25519(ref d, b);
      return CryptoVerify32(c, 0, d, 0);
    }

    private static Int64 Unpackneg(ref Int64[][] r, ref byte[] p)
    {
      Int64[] t = Gf();
      Int64[] chk = Gf();
      Int64[] num = Gf();
      Int64[] den = Gf();
      Int64[] den2 = Gf();
      Int64[] den4 = Gf();
      Int64[] den6 = Gf();

      Set25519(ref r[2], gf1);
      Unpack25519(ref r[1], p);
      S(ref num, r[1]);
      var d = D;
      M(ref den, ref num, ref d);
      Z(ref num, ref num, ref r[2]);
      A(ref den, ref r[2], ref den);

      S(ref den2, den);
      S(ref den4, den2);
      M(ref den6, ref den4, ref den2);
      M(ref t, ref den6, ref num);
      M(ref t, ref t, ref den);

      Pow2523(ref t, ref t);
      M(ref t, ref t, ref num);
      M(ref t, ref t, ref den);
      M(ref t, ref t, ref den);
      M(ref r[0], ref t, ref den);

      S(ref chk, r[0]);
      M(ref chk, ref chk, ref den);

      if (Neq25519(chk, num) != 0)
      {
        var i = I;
        M(ref r[0], ref r[0], ref i);
      }

      S(ref chk, r[0]);
      M(ref chk, ref chk, ref den);
      if (Neq25519(chk, num) != 0)
      {
        return -1;
      }

      if (Par25519(r[0]) == (p[31] >> 7))
      {
        Int64[] tmp = Gf();
        Z(ref r[0], ref tmp, ref r[0]);
      }
      M(ref r[3], ref r[0], ref r[1]);
      return 0;
    }

    //why do we negate points when unpacking them???
    public static void GeNeg(ref byte[] pub)
    {
      pub[31] ^= 0x80;
    }

    //res = s*P
    public static byte[] GeScalarmult(byte[] P, byte[] s)
    {
      Int64[][] p = { Gf(), Gf(), Gf(), Gf() };
      Int64[][] upk = { Gf(), Gf(), Gf(), Gf() };


      byte[] res = new byte[32];

      GeNeg(ref P);
      if (Unpackneg(ref upk, ref P) != 0)
      {
        throw new Exception("non-0 error on point decode");
      }

      Scalarmult(ref p, ref upk, ref s);
      Pack(ref res, p);
      return res;

    }

    public static byte[] GeDoubleScalarmultBaseVartime(byte[] c, byte[] P, byte[] r)
    {
      if (c.Length != 32 || P.Length != 32 || r.Length != 32)
      {
        throw new Exception("Invalid input length!");
      }

      Int64[][] uP = { Gf(), Gf(), Gf(), Gf() };
      Int64[][] cP = { Gf(), Gf(), Gf(), Gf() };
      Int64[][] rG = { Gf(), Gf(), Gf(), Gf() };

      byte[] res = new byte[32];

      GeNeg(ref P);

      if (Unpackneg(ref uP, ref P) != 0)
      {
        throw new Exception("non-0 error on point decode");
      }

      Parallel.Invoke(
          () => Scalarmult(ref cP, ref uP, ref c),
          () => Scalarbase(ref rG, r)
      );
      Add(ref rG, ref cP);
      Pack(ref res, rG);
      return res;
    }
    private static Int64[] Gf(Int64[] init = null)
    {
      UInt32 i = 0;
      Int64[] r = new Int64[16]; // Float64Array(16) in javascript
      if (init != null)
      {
        for (i = 0; i < init.Length; ++i)
        {
          r[i] = init[i];
        }
      }
      return r;
    }

    public static byte[] GeSub(ref byte[] P, ref byte[] Q)
    {
      GeNeg(ref Q);
      return GeAdd(P, Q);
    }

    public static byte[] GeDoubleScalarmultPostcompVartime(byte[] r, byte[] P, byte[] c, byte[] I)
    {
      if (c.Length != 32 || P.Length != 32 || r.Length != 32 || I.Length != 32)
      {
        throw new Exception("Invalid input length!");
      }

      byte[] Pb = CryptonoteUtils.HashToEc2(P);
      Int64[][] uPb = { Gf(), Gf(), Gf(), Gf() };
      Int64[][] uI = { Gf(), Gf(), Gf(), Gf() };
      Int64[][] cI = { Gf(), Gf(), Gf(), Gf() };
      Int64[][] rPb = { Gf(), Gf(), Gf(), Gf() };

      byte[] res = new byte[32];
      GeNeg(ref Pb);
      if (Unpackneg(ref uPb, ref Pb) != 0)
      {
        throw new Exception("non-0 error on point decode");
      }

      Scalarmult(ref rPb, ref uPb, ref r);
      GeNeg(ref I);
      if (Unpackneg(ref uI, ref I) != 0)
      {
        throw new Exception("non-0 error on point decode");
      }
      Scalarmult(ref cI, ref uI, ref c);
      Add(ref rPb, ref cI);
      Pack(ref res, rPb);
      return res;

    }

    public static byte[] GeAdd(byte[] P, byte[] Q)
    {
      Int64[][] uP = { Gf(), Gf(), Gf(), Gf() };
      Int64[][] uQ = { Gf(), Gf(), Gf(), Gf() };

      byte[] res = new byte[32];
      GeNeg(ref P);
      GeNeg(ref Q);
      if (Unpackneg(ref uP, ref P) != 0 || Unpackneg(ref uQ, ref Q) != 0)
      {
        throw new Exception("non-0 error on point decode");
      };
      Add(ref uP, ref uQ);
      Pack(ref res, uP);
      return res;
    }
  }
}
