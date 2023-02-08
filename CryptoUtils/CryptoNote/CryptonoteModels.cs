using System;
using System.Collections.Generic;

namespace CryptoUtils.CryptoNote
{
  
  public struct PObject
  {
    public RvObject[] Mgs;
    public Sig[] RangeSigs;
  }

  public struct RvObject
  {
    public string cc;
    public List<string[]> ss;
  }

  public struct RctSignatures
  {
    public MaskAmount[] EcdhInfo;
    public string Message;
    public string[] OutPk;
    public PObject P;
    public string[] PseudoOuts;
    public Int32 Type;
    public string TxnFee;
  }
  public struct BSig
  {
    public List<string[]> s;
    public string ee;
  }

  public struct Sig
  {
    public string[] Ci;
    public BSig Bsig;
  }

  public struct MaskAmount
  {
    public string Amount;
    public string Mask;
  }

  public class GeP2
  {
    public GeP2()
    {
      X = new Int32[10];
      Y = new Int32[10];
      Z = new Int32[10];
    }
    public Int32[] X;
    public Int32[] Y;
    public Int32[] Z;
  }

  public class GeP3
  {
    public GeP3()
    {
      X = new Int32[10];
      Y = new Int32[10];
      Z = new Int32[10];
      T = new Int32[10];
    }
    public Int32[] X;
    public Int32[] Y;
    public Int32[] Z;
    public Int32[] T;
  }

  public class GeP1P1
  {
    public GeP1P1()
    {
      X = new Int32[10];
      Y = new Int32[10];
      Z = new Int32[10];
      T = new Int32[10];
    }
    public Int32[] X;
    public Int32[] Y;
    public Int32[] Z;
    public Int32[] T;
  }

  public class GeCached
  {
    public GeCached()
    {
      YplusX = new Int32[10];
      YminusX = new Int32[10];
      Z = new Int32[10];
      T2d = new Int32[10];
    }
    public Int32[] YplusX;
    public Int32[] YminusX;
    public Int32[] Z;
    public Int32[] T2d;
  }


  

}
