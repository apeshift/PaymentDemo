using System;
using System.Threading;
using System.Threading.Tasks;
using ApeShiftWeb;
using Newtonsoft.Json;

namespace ApeShift
{

  public class ApeSession
  {

    public event NoxProfileRequestCompletedEventHandler _OnRequest;
    public string _APEMQ_CONNECTION_TOKEN;
  
    public ApeMQ apeMQ = new ApeMQ();

    ApeAPI _ApeAPI;

    public ApeSession(string APEAPI_SECRET, string APEAPI_PUBLIC_ID, string APEMQ_CONNECTION_TOKEN, string MY_PRIVATE_KEY)
    {
      _APEMQ_CONNECTION_TOKEN = APEMQ_CONNECTION_TOKEN;
      _ApeAPI = new ApeAPI(APEAPI_SECRET, APEAPI_PUBLIC_ID);

      apeMQ._OnMsg += Processor_MSGEvent;
      apeMQ.StartWS(_APEMQ_CONNECTION_TOKEN);

    }

    public async Task<string> APIRequest(api_methods method, object obj)
    { 
      return await _ApeAPI.Request(method, obj);
    }

    void Processor_MSGEvent(DataMSGCompletedEventArgs processor)
    {
      if (processor.Message.IndexOf("error") == 0)
      {
        WriteLogMsg2("MQ REStarted" + DateTime.Now.ToString());
        apeMQ.StartWS(_APEMQ_CONNECTION_TOKEN);
        return;
      }

      try
      {

        var result = JsonConvert.DeserializeObject<MQResponse<MQDiffieResult>>(processor.Message).Result;

        if (result == null)
          return;

        RequestArrived(result.ProtectedMessage);

        WriteLogMsg2("Arrived : " + result.ProtectedMessage);
      }
      catch (Exception ex)
      {
        WriteLogMsg2("MQ Error : " + ex.Message);
      }
    }

    public void WriteLogMsg2(string msg)
    {
      Console.WriteLine(msg);
    }

    public void RequestArrived(string request)
    {
      try
      {
        if (request == null)
          return;

        if (_OnRequest == null)
          return;

       _OnRequest.Invoke(new NoxProfileRequestCompletedEventArgs(request));

      }
      catch { }
    }

  }


  public delegate void DataMSGCompletedEventHandler(DataMSGCompletedEventArgs e);
  public partial class DataMSGCompletedEventArgs : System.ComponentModel.AsyncCompletedEventArgs
  {
    public DataMSGCompletedEventArgs(object result) : base(null, false, null) { Message = (string)result; }
    public string Message { get; }
  }

  public delegate void NoxProfileRequestCompletedEventHandler(NoxProfileRequestCompletedEventArgs e);
  public partial class NoxProfileRequestCompletedEventArgs : System.ComponentModel.AsyncCompletedEventArgs
  {
    public NoxProfileRequestCompletedEventArgs(string result) : base(null, false, null)
    { Request = result; }
    public string Request { get; }
  }

  public delegate void NoxProfileResponseCompletedEventHandler(NoxProfileResponseCompletedEventArgs e);
  public partial class NoxProfileResponseCompletedEventArgs : System.ComponentModel.AsyncCompletedEventArgs
  {
    public NoxProfileResponseCompletedEventArgs(string result) : base(null, false, null)
    { Response = result; }
    public string Response { get; }
  }

}
