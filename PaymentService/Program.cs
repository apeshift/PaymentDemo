using System;
using System.Threading;

namespace PaymentService
{
  class Program
  {
    static void Main(string[] args)
    {

      new Thread(() =>
        {

          UTMQProcessor orderManager = new UTMQProcessor(ApiConfig.APEAPI_SECRET, ApiConfig.APEAPI_PUBLIC_ID, ApiConfig.BLOCKMQ_CONNECTION_TOKEN);

          SphereProcessor sphereProcessor = new SphereProcessor(ApiConfig.APEAPI_SECRET, ApiConfig.APEAPI_PUBLIC_ID, ApiConfig.APPMQ_CONNECTION_TOKEN, ApiConfig.MY_PRIVATE_KEY, ApiConfig.EXTENDED_PUB_KEY, ApiConfig.MY_PRIVATE_KEY);

        }).Start();

      Console.ReadLine();

    }
  }

}
