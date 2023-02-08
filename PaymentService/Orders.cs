using NBitcoin;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PaymentService
{
  class Orders
  {
    public static ConcurrentDictionary<string, OrderTask> OrderTasks = new ConcurrentDictionary<string, OrderTask>();
  }
  public class OrderManager
  {
    public async static Task UpdateOrderTask(string OrderID, string TxnEvent)
    {

      if (!Orders.OrderTasks.ContainsKey(OrderID))
        return;
      
      OrderTask orderTask = Orders.OrderTasks[OrderID];

      if (orderTask.Completed) 
        return;
      
      orderTask.Completed = true;

      OrderResponse response = new OrderResponse()
      {
        PageElements = OrderManager.BTC_SuccessElements()
      };

      await SphereProcessor.Current.InvokeClient(orderTask.EnvoyTaskID, response, 0, orderTask.ClientKey);

    }
    
    public static Elements[] CC_ProcessingElements()
    {
      List<Elements> elements = new List<Elements>();

      elements.Add(new Elements()
      {
        ID = "card_info",
        Show = false,
        Hide = true,
        B64Value = false,
        TextContent = ""
      });

      elements.Add(new Elements()
      {
        ID = "address_info",
        Show = false,
        Hide = true,
        B64Value = false,
        TextContent = ""
      });

      elements.Add(new Elements()
      {
        ID = "status_info",
        Show = true,
        Hide = false,
        B64Value = false,
        TextContent = "",

      });

      elements.Add(new Elements()
      {
        ID = "status_title",
        Show = true,
        Hide = false,
        B64Value = false,
        TextContent = "waiting for payment",

      });

      elements.Add(new Elements()
      {
        ID = "status_message",
        Show = true,
        Hide = false,
        B64Value = false,
        TextContent = "requesting payment capture",

      });


      return elements.ToArray();
    }

    public static Elements[] CC_SuccessElements()
    {
      List<Elements> elements = new List<Elements>();

      elements.Add(new Elements()
      {
        ID = "card_info",
        Show = false,
        Hide = true,
        B64Value = false,
        TextContent = ""
      });

      elements.Add(new Elements()
      {
        ID = "address_info",
        Show = false,
        Hide = true,
        B64Value = false,
        TextContent = ""
      });

      elements.Add(new Elements()
      {
        ID = "status_info",
        Show = true,
        Hide = false,
        B64Value = false,
        TextContent = "",

      });

      elements.Add(new Elements()
      {
        ID = "status_title",
        Show = true,
        Hide = false,
        B64Value = false,
        TextContent = "Success!",

      });

      elements.Add(new Elements()
      {
        ID = "status_message",
        Show = true,
        Hide = false,
        B64Value = false,
        TextContent = "payment captured",

      });
      elements.Add(new Elements()
      {
        ID = "status_check",
        Show = true,
        Hide = false,
        B64Value = false,
        TextContent = ""
      });

      return elements.ToArray();
    }

    public static Elements[] CC_StartElements()
    {
      List<Elements> elements = new List<Elements>();

      elements.Add(new Elements()
      {
        ID = "card_info",
        Show = true,
        Hide = false,
        B64Value = false,
        TextContent = ""
      });

      elements.Add(new Elements()
      {
        ID = "address_info",
        Show = false,
        Hide = true,
        B64Value = false,
        TextContent = ""
      });

      elements.Add(new Elements()
      {
        ID = "status_info",
        Show = false,
        Hide = true,
        B64Value = false,
        TextContent = ""
      });

      return elements.ToArray();
    }

    public static Elements[] BTC_StartElements(string address)
    {
      List<Elements> elements = new List<Elements>();

      elements.Add(new Elements()
      {
        ID = "card_info",
        Show = false,
        Hide = true,
        B64Value = false,
        TextContent = ""
      });

      elements.Add(new Elements()
      {
        ID = "address_info",
        Show = true,
        Hide = false,
        B64Value = false,
        TextContent = ""
      });

      elements.Add(new Elements()
      {
        ID = "payin_address",
        Show = true,
        Hide = false,
        B64Value = false,
        TextContent = address
      });

      elements.Add(new Elements()
      {
        ID = "status_info",
        Show = false,
        Hide = true,
        B64Value = false,
        TextContent = ""
      });

      return elements.ToArray();
    }

    public static Elements[] BTC_SuccessElements()
    {
      List<Elements> elements = new List<Elements>();

      elements.Add(new Elements()
      {
        ID = "card_info",
        Show = false,
        Hide = true,
        B64Value = false,
        TextContent = ""
      });

      elements.Add(new Elements()
      {
        ID = "address_info",
        Show = false,
        Hide = true,
        B64Value = false,
        TextContent = ""
      });

      elements.Add(new Elements()
      {
        ID = "status_info",
        Show = true,
        Hide = false,
        B64Value = false,
        TextContent = "",

      });

      elements.Add(new Elements()
      {
        ID = "status_title",
        Show = true,
        Hide = false,
        B64Value = false,
        TextContent = "Success!",

      });

      elements.Add(new Elements()
      {
        ID = "status_message",
        Show = true,
        Hide = false,
        B64Value = false,
        TextContent = "payment detected",

      });
      elements.Add(new Elements()
      {
        ID = "status_check",
        Show = true,
        Hide = false,
        B64Value = false,
        TextContent = ""
      });

      return elements.ToArray();
    }
  }



}
