using ApeShift;
using ApeShiftWeb;
using CryptoUtils;
using NBitcoin;
using Newtonsoft.Json;
using PayPalServices;
using System;
using System.Collections.Concurrent;
using System.Text;
using System.Threading;
using System.Threading.Tasks;


namespace PaymentService
{
  class SphereProcessor
  {
    public static SphereProcessor Current { get; private set; }

    public ConcurrentDictionary<string, decimal> _RateSpot;

    CancellationTokenSource cancellationToken;

    ApeSession _ApeSession;

    public PrivateSession _PrivateSession;

    Key _SecretKey;

    string _EXTENDED_PUB_KEY;

    public SphereProcessor(string APEAPI_SECRET, string APEAPI_PUBLIC_ID, string APEMQ_CONNECTION_TOKEN, string MY_PRIVATE_KEY,
      string EXTENDED_PUB_KEY, string SECRET_SESSION_KEY)
    {
      if (Current != null)
        return;

      Current = this;

      _EXTENDED_PUB_KEY = EXTENDED_PUB_KEY;
      cancellationToken = new CancellationTokenSource();
      _RateSpot = new ConcurrentDictionary<string, decimal>();
      _SecretKey = new Key(SECRET_SESSION_KEY.HexToByteArray());
      _PrivateSession = new PrivateSession(_SecretKey.ToBytes());

      _ApeSession = new ApeSession(APEAPI_SECRET, APEAPI_PUBLIC_ID, APEMQ_CONNECTION_TOKEN, MY_PRIVATE_KEY);

      _ApeSession._OnRequest += OnMQEvent;
    }

    public void Stop()
    {
      cancellationToken.Cancel();
      _ApeSession._OnRequest -= OnMQEvent;
    }

    async Task ProcessRequest(OrderRequest Req, string OrderID, byte[] ClientKey)
    {
      try
      {

        if (Req.Method == RequestMethods.submit_cc_token)
        {
          if (!Orders.OrderTasks.ContainsKey(OrderID))
          {
            throw new PayPalException("Invalid request, order not started.");
          }

          if (string.IsNullOrEmpty(Req.Card_Token))
          {
            throw new PayPalException("Invalid credit card token.");
          }

          OrderTask orderTask = Orders.OrderTasks[OrderID];

          if (orderTask.Completed)
          {
            throw new PayPalException("Already paid.");
          }

          OrderResponse temp = new OrderResponse()
          {
            PageElements = OrderManager.CC_ProcessingElements()
          };

          await InvokeClient(orderTask.EnvoyTaskID, temp, 30, ClientKey);

          var pp_resp = await PayPal.CapturePayment(Req.Card_Token);

          if (pp_resp.Success)
          {
            orderTask.Completed = true;

            OrderResponse response = new OrderResponse()
            {
              VerboseInfo = pp_resp.Response,
              PageElements = OrderManager.CC_SuccessElements()
            };

            await InvokeClient(orderTask.EnvoyTaskID, response, 0, ClientKey);
          }
          else
          {

            var pporder = PayPal.GetRequestBody(OrderID);
            orderTask.PayPalSession.OrderID = await PayPal.CreateOrder(pporder);

            OrderResponse response = new OrderResponse()
            {
              VerboseInfo = pp_resp.Response,

              PayPalSession = orderTask.PayPalSession,

              ErrorResponse = new ErrorResponse()
              {
                Title = "paypal response",
                Message = pp_resp.Message,
                TryAgain = true
              }
            };

            await InvokeClient(orderTask.EnvoyTaskID, response, 30, ClientKey);
          }

        }

        if (Req.Method == RequestMethods.session_start)
        {

          if (Orders.OrderTasks.ContainsKey(OrderID))
            return;

          if (Req.PayMethod == "card")
          {

            var payPalSesion = new PayPalSesion();
            var orderType = OrderType.credit_card;
            var startElements = OrderManager.CC_StartElements();

            var pporder = PayPal.GetRequestBody(OrderID);
            payPalSesion.Token = await PayPal.CreateClientToken();
            payPalSesion.OrderID = await PayPal.CreateOrder(pporder);

            payPalSesion.Endpoint = "https://www.paypal.com/sdk/js?components=hosted-fields,buttons&client-id=" + PayPalServices.ConfigValues.PAYPAL_CLIENTID;

            OrderTask orderTask = new OrderTask()
            {
              PayPalSession = payPalSesion,
              ClientKey = ClientKey,
              EnvoyTaskID = Req.EnvoyTaskID,
              OrderType = orderType,
              DepositAddress = "",
            };

            if (Orders.OrderTasks.TryAdd(OrderID, orderTask))
            {
              OrderResponse response = new OrderResponse()
              {
                PayPalSession = payPalSesion,
                PageElements = startElements
              };

              await InvokeClient(orderTask.EnvoyTaskID, response, 30, ClientKey);
            }

          }
          else
          {
            var count = await _ApeSession.APIRequest(api_methods.get_address_count, new AddressCountRequest()
            {
              network = "grs_testnet",
              queue_name = "import"
            });

            var address = GetPayementAddress(JsonConvert.DeserializeObject
              <JResponseWrapper<AddressCountResponse>>(count).Result.address_count);

            var subscribe = await _ApeSession.APIRequest(api_methods.subscribe, new SubscibeRequest()
            {
              address = address,
              include_data = OrderID.ToB64(),
              network = "grs_testnet",
              queue_name = "import"
            });

            Elements[] startElements = OrderManager.BTC_StartElements(address);
            var orderType = OrderType.bitcoin;

            OrderTask orderTask = new OrderTask()
            {
              ClientKey = ClientKey,
              EnvoyTaskID = Req.EnvoyTaskID,
              OrderType = orderType,
              DepositAddress = address,
            };

            if (Orders.OrderTasks.TryAdd(OrderID, orderTask))
            {
              OrderResponse response = new OrderResponse()
              {
                PageElements = startElements
              };

              await InvokeClient(orderTask.EnvoyTaskID, response, 30, ClientKey);
            }

          }

        }

      }
      catch (Exception ex)
      {

        Console.WriteLine(ex.Message);

        if (Orders.OrderTasks.ContainsKey(OrderID))
        {
          OrderResponse response = new OrderResponse()
          {
            VerboseInfo = ex.Message,

            ErrorResponse = new ErrorResponse()
            {
              Title = "service says",
              Message = ex.Message,
              TryAgain = false
            }
          };

          await InvokeClient(Orders.OrderTasks[OrderID].EnvoyTaskID, response, 0, ClientKey);
        }
      
      }
    }
    static string GetPayementAddress(int index)
    {
      ExtPubKey ext = new ExtPubKey(ApiConfig.EXTENDED_PUB_KEY);
      Network network = NBitcoin.Altcoins.Groestlcoin.Instance.Testnet;
      var xkey = ext.Derive(index, false);
      return xkey.PubKey.Compress(false).GetAddress(network).ToString();
    }
    void OnMQEvent(NoxProfileRequestCompletedEventArgs req)
    {
      try
      {

        bool success = _PrivateSession.TryDecrypt(Convert.FromBase64String(req.Request), out DecryptResult result);

        Console.WriteLine("success: " + success);

        if (!success)
          return;

        var Req = JsonConvert.DeserializeObject<OrderRequest>(Encoding.UTF8.GetString(result.message));
        string OrderID = new Key(result.ephemeralKey).PubKey.Compress(true).ToBytes().ToHex();

        Console.WriteLine("Order: " + OrderID);

        Task.Run(async () =>
        {
          await ProcessRequest(Req, OrderID, result.ephemeralKey);
        });

      }
      catch { }

    }
    public async Task InvokeClient(string ApeTaskID, object objResponse, uint NewTimeout, byte[] ClientKey)
    {
      try
      {
        var json = JsonConvert.SerializeObject(objResponse);

        var encrypted = _PrivateSession.Encrypt(System.Text.Encoding.UTF8.GetBytes(json), ClientKey);

        string msg = Convert.ToBase64String(encrypted);

        await _ApeSession.APIRequest(api_methods.invoke_envoy, new InvokeEnvoyRequest()
        {
          new_timeout = NewTimeout,
          message = msg,
          task_id = ApeTaskID
        });
      }
      catch { }
    }

  }

}
