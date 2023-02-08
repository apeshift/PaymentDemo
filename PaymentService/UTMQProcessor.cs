using System;
using System.Threading.Tasks;
using ApeShift;
using ApeShiftWeb;
using CryptoUtils;
using Newtonsoft.Json;

namespace PaymentService
{

  public class UTMQProcessor
  {
    public static UTMQProcessor Current { get; private set; }

    public string _APEAPI_SECRET;
    public string _APEAPI_PUBLIC_ID;
    public string _APEMQ_CONNECTION_TOKEN;

    ApeBCMQ apeMQ = new ApeBCMQ();

    ApeAPI _ApeAPI;

    public UTMQProcessor(string APEAPI_SECRET, string APEAPI_PUBLIC_ID, string APEMQ_CONNECTION_TOKEN)
    {

      if (Current != null)
        return;

      Current = this;

      _APEAPI_PUBLIC_ID = APEAPI_PUBLIC_ID;
      _APEAPI_SECRET = APEAPI_SECRET;
      _APEMQ_CONNECTION_TOKEN = APEMQ_CONNECTION_TOKEN;
      _ApeAPI = new ApeAPI(_APEAPI_SECRET, _APEAPI_PUBLIC_ID);

      apeMQ._OnMsg += Processor_MSGEvent;
      apeMQ.StartWS(_APEMQ_CONNECTION_TOKEN);

    }

    async Task ProcessEvent(MQNetworkResult networkResult)
    {

      try
      {
        string OrderID = networkResult.UserData.FromB64();

        await OrderManager.UpdateOrderTask(OrderID, networkResult.TxnEvent);
      }
      catch { }
    }

    void Processor_MSGEvent(DataMSGCompletedEventArgs processor)
    {
      if (processor.Message.IndexOf("error") == 0)
      {
        apeMQ.StartWS(_APEMQ_CONNECTION_TOKEN);
        Console.WriteLine("RESTARTING APEMQ", System.Diagnostics.TraceLevel.Verbose);
        return;
      }

      Task.Run(async () =>
      {
        try
        {
          var resp = JsonConvert.DeserializeObject<MQResponse<MQNetworkResult>>(processor.Message);

          if (resp == null)
            return;

          var mq = resp.Result;
          if (mq == null)
            return;

          if (string.IsNullOrEmpty(mq.TxnId))
            return;


          await ProcessEvent(mq);

        }
        catch (Exception ex)
        {
          Console.WriteLine(ex.Message);
        }

      });

    }

  }



}

