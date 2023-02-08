using System;

namespace PaymentService
{
  public enum OrderType { credit_card = 1, bitcoin = 2 }
  public class OrderTask
  {
    public OrderType OrderType { get; set; }
    public string DepositAddress { get; set; }
    public PayPalSesion PayPalSession { get; set; }
    public byte[] ClientKey { get; set; }
    public string EnvoyTaskID { get; set; }
    public bool Completed { get; set; }

  }
  public enum RequestMethods
  {
    session_start = 1,
    submit_cc_token = 2,
    submit_btc_address = 3
  }
  public class OrderRequest
  {
    public string PayMethod { get; set; }
    public string EnvoyTaskID { get; set; }
    public string BTC_Address { get; set; }
    public string Card_Token { get; set; }
    public RequestMethods Method { get; set; }
  }

  public class OrderResponse
  {
    public string VerboseInfo { get; set; }
    public PayPalSesion PayPalSession { get; set; }
    public Elements[] PageElements { get; set; }
    public ErrorResponse ErrorResponse { get; set; }
  }

  public class Elements
  {
    public string ID { get; set; }
    public bool Show { get; set; }
    public bool Hide { get; set; }
    public string TextContent { get; set; }
    public bool B64Value { get; set; }

  }

  public class PayPalSesion
  {
    public string OrderID { get; set; }
    public string Token { get; set; }
    public string Endpoint { get; set; }
  }

  public class ErrorResponse
  {
    public string Title { get; set; }
    public string Message { get; set; }
    public bool TryAgain { get; set; }

  }


  public class BTCException : Exception
  {
    public BTCException(string Message) : base(Message)
    {

    }

    public BTCException(string Message, Exception Inner) : base(Message, Inner)
    {

    }

  }

  public class PayPalException : Exception
  {
    public PayPalException(string Message) : base(Message)
    {

    }

    public PayPalException(string Message, Exception Inner) : base(Message, Inner)
    {

    }

  }

}
