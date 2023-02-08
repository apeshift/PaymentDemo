using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using PayPalCheckoutSdk.Core;
using PayPalCheckoutSdk.Orders;

namespace PayPalServices
{
  class ConfigValues
  {
    public const string PAYPAL_CLIENTID = "";
    public const string PAYPAL_CLIENTSECRET = "";
  }
  public class PayPalClient
  {
    public static PayPalEnvironment test_environment()
    {
      return new SandboxEnvironment(ConfigValues.PAYPAL_CLIENTID, ConfigValues.PAYPAL_CLIENTSECRET);
    }
    public static PayPalEnvironment environment()
    {
      var env = test_environment();
      return env;
    }
    public static PayPalHttp.HttpClient client()
    {
      var ppcli = new PayPalHttpClient(environment());

      ppcli.SetConnectTimeout(TimeSpan.FromSeconds(20000));
      return ppcli;
    }

    public static PayPalHttp.HttpClient client(string refreshToken)
    {
      return new PayPalHttpClient(environment(), refreshToken);
    }
  }
  public class PayPal
  {

    private async static Task<string> GetClientToken(string AccessToken)
    {
      try
      {
        var uriBuilder = new UriBuilder("https://api.sandbox.paypal.com/v1/identity/generate-token");
        using (var client = new System.Net.Http.HttpClient())
        {
          client.Timeout = TimeSpan.FromMilliseconds(5000);
          client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", AccessToken);
          var content = new StringContent("");
          using (var response = await client.PostAsync(uriBuilder.Uri, null))
          {
            var responseString = await response.Content.ReadAsStringAsync();
            PPResp resp = JsonConvert.DeserializeObject<PPResp>(responseString);
            return resp.client_token;
          }
        }
      }
      catch (HttpRequestException)
      {
        return null;
      }
      catch (TaskCanceledException)
      {
        return null;
      }
    }

    public async static Task<string> CreateClientToken()
    {

      AccessTokenRequest accessTokenRequest = new AccessTokenRequest(PayPalClient.environment());
      var atr = await PayPalClient.client().Execute(accessTokenRequest);
      var at = atr.Result<AccessToken>();

      return await GetClientToken(at.Token);
    }
    public async static Task<string> CreateOrder(OrderRequest orderRequest)
    {
      var request = new OrdersCreateRequest();
      request.Prefer("return=representation");
      request.RequestBody(orderRequest);
      var response = await PayPalClient.client().Execute(request);
      var result = response.Result<Order>();
      return result.Id;
    }
    public async static Task<BTreeResp> CapturePayment(string OrderId)
    {

      BTreeResp bTreeResp = new BTreeResp();

      try
      {

        var request = new OrdersCaptureRequest(OrderId);
        request.Prefer("return=representation");
        request.RequestBody(new OrderActionRequest());
        var response = await PayPalClient.client().Execute(request);
        var result = response.Result<Order>();

        JsonSerializerSettings js = new JsonSerializerSettings();
        js.Formatting = Formatting.Indented;

        bTreeResp.Response = JsonConvert.SerializeObject(result, js);
        bTreeResp.TxnID = result.Id;

        if (result.Status == "COMPLETED")
        {
          foreach (var capture in result.PurchaseUnits[0].Payments.Captures)
          {
            if (capture.Status == "COMPLETED")
            {
              bTreeResp.Success = true;
              break;
            }
          }

          if (!bTreeResp.Success)
          {
            bTreeResp.Message = result.PurchaseUnits[0].Payments.Captures
              [result.PurchaseUnits[0].Payments.Captures.Count - 1].Status;
          }
        }

      }
      catch (Exception ex)
      {
        bTreeResp.Message = ex.Message;
      }

      if (!bTreeResp.Success && string.IsNullOrEmpty(bTreeResp.Message))
      {
        bTreeResp.Message = "UNABLE TO PROCESS CARD. Please try again.";
      }

      return bTreeResp;
    }
    public static OrderRequest GetRequestBody(string OrderID)
    {
      OrderRequest orderRequest = new OrderRequest()
      {

        CheckoutPaymentIntent = "CAPTURE",
        ApplicationContext = new ApplicationContext
        {
          BrandName = "ASYNC360",
          LandingPage = "BILLING",
          UserAction = "PAY_NOW",
          ShippingPreference = "SET_PROVIDED_ADDRESS"
        },
        Payer = new Payer
        {
          Name = new Name
          {
            GivenName = "TEST",
            Surname = "APE"
          },
          Email = OrderID + "@async360.com",
          AddressPortable = new AddressPortable
          {
            AddressLine1 = "156 Main St",
            AddressLine2 = "STE 101",
            AdminArea2 = "Springfield",
            AdminArea1 = "NC",
            PostalCode = "28803",
            CountryCode = "US"
          },

        },
        PurchaseUnits = new List<PurchaseUnitRequest>
        {
          new PurchaseUnitRequest{
            Description = "APE COMPARE",
            CustomId = OrderID,
            AmountWithBreakdown = new AmountWithBreakdown
            {
              CurrencyCode = "USD",
              Value = "10",
              AmountBreakdown = new AmountBreakdown
              {
                ItemTotal = new Money
                {
                  CurrencyCode = "USD",
                  Value = "10",
                },
                Discount = new Money
                {
                   CurrencyCode = "USD",
                   Value = "0",
                },
                Shipping = new Money
                {
                  CurrencyCode = "USD",
                  Value = "0",
                }

              }
            },
            Items = new List<Item>
            {
              new Item
              {
                Name = "APE STUFF",
                Description = "APE GEN2",

                UnitAmount = new Money
                {
                  CurrencyCode = "USD",
                  Value = "10"
                },

                Quantity = "1",
                Category = "PHYSICAL_GOODS"
              },

            },
            ShippingDetail = new ShippingDetail
            {
              Name = new Name
              {
                FullName = "TEST APE"
              },
              AddressPortable = new AddressPortable
              {
            AddressLine1 = "156 Main St",
            AddressLine2 = "STE 101",
            AdminArea2 = "Springfield",
            AdminArea1 = "NC",
            PostalCode = "28803",
            CountryCode = "US"

              }
            }
          }
        }
      };

      return orderRequest;
    }

    public class PPResp
    {
      public string client_token { get; set; }

    }
    public class BTreeResp
    {
      public string Response { get; set; }
      public string TxnID { get; set; }
      public bool Success { get; set; }
      public string Message { get; set; }
    }
  }
}