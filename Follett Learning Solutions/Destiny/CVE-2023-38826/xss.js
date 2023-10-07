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
    request.open('GET', 'https://xxxx.ngrok.app/login.html', true);

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