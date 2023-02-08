using ApeShiftWeb;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.WebSockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ApeShift
{
  public class ApeMQ
  {
    public event DataMSGCompletedEventHandler _OnMsg;

    ClientWebSocket webSocket;

    CancellationTokenSource _token;

    public void StartWS(string APEMQ_CONNECTION_TOKEN)
    {
      _token = new CancellationTokenSource();
      webSocket = new ClientWebSocket();
      webSocket.Options.SetRequestHeader("Connection-Token", APEMQ_CONNECTION_TOKEN);

      Task t = Task.Run(async () =>
      {
        try
        {
           await webSocket.ConnectAsync(new Uri("wss://app.async360.com/"), CancellationToken.None);


          LocallyHandleMessageArrived("start");

          await RunWS();
        }
        catch (ThreadAbortException)
        {
          try
          {
            if (!_token.IsCancellationRequested)
              _token.Cancel();
          }
          catch { }

          await WSClose();

          LocallyHandleMessageArrived("abort");

        }
        catch (Exception ex)
        {
          try
          {
            if (!_token.IsCancellationRequested)
              _token.Cancel();
          }
          catch { }

          await WSClose();

          LocallyHandleMessageArrived("error: " + ex.Message);
        }

      });
    }

    private async Task RunWS()
    {
      while (webSocket.State == WebSocketState.Open)
      {

        var msg = await GetMessageResponse();

        LocallyHandleMessageArrived(msg);

        await PopMsg(msg);

      }

      throw new Exception("disconnected");
    }

    private async Task PopMsg(string Message)
    {
      if (string.IsNullOrEmpty(Message))
        return;

      MQResponse<object> resp = JsonConvert.DeserializeObject<MQResponse<object>>(Message);

      await Send(resp.DequeueCommand);

    }
    private async Task<string> xxGetMessageResponse()
    {

      ArraySegment<byte> in_buffer = new ArraySegment<byte>(new byte[5 * 1024]);
      WebSocketReceiveResult result = await webSocket.ReceiveAsync(in_buffer, _token.Token);
      if (result == null || result.Count == 0)
        throw new Exception("cancelled");

      return Encoding.UTF8.GetString(in_buffer.Array, 0, result.Count);
    }

    private async Task<string> GetMessageResponse()
    {
      List<byte[]> received = new List<byte[]>();

      while (true)
      {
        try
        {
          ArraySegment<byte> in_buffer = new ArraySegment<byte>(new byte[1024]);
          WebSocketReceiveResult result = await webSocket.ReceiveAsync(in_buffer, _token.Token);

          if (result == null || result.Count == 0)
            break;

          byte[] resp = new byte[result.Count];
          Buffer.BlockCopy(in_buffer.Array, 0, resp, 0, result.Count);
          received.Add(resp);

          if (result.EndOfMessage || result.Count == 0)
            break;
        }
        catch { break; }
      }

      byte[] eomresp = new byte[0];
      var bref = eomresp.MConcat(received.ToArray());
      return Encoding.UTF8.GetString(bref);
    }

    public async Task Send(string Msg)
    {
      var array = Encoding.UTF8.GetBytes(Msg);
      var buffer = new ArraySegment<byte>(array);
      await webSocket.SendAsync(buffer, WebSocketMessageType.Text, true, _token.Token);
    }

    public async Task WSClose()
    {
      if (webSocket.State != WebSocketState.Open)
        return;

      try
      {
        await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "user", CancellationToken.None);
      }
      catch { }
    }

    void LocallyHandleMessageArrived(string msg)
    {
      if (_OnMsg == null) return;

      try
      {
        Interlocked.CompareExchange(ref _OnMsg, null, null)?.Invoke(new DataMSGCompletedEventArgs(msg));
      }
      catch { }
    }
  }


  static class WSExtensions
  {

    public static byte[] MConcat(this byte[] arr, params byte[][] arrs)
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
