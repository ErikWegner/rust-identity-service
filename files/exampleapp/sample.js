let csrftoken = '';

const isLoggedIn = () =>
    fetch('/auth/status')
        .then((response) => response.json())
        .then((isLoggedInData) => {
            document.getElementById('loginStatus').innerHTML =
                isLoggedInData.authenticated
                    ? `authenticated (exp: ${isLoggedInData.expires_in}, refexp: ${isLoggedInData.refresh_expires_in})`
                    : 'not authenticated';
            document.getElementById('csrftoken').innerText = csrftoken;
        });

setInterval(isLoggedIn, 1000);

window.addEventListener('message', (event) => {
    const o = {
        origin: event.origin,
        data: event.data,
    };
    document.getElementById('echoresponse').innerText = JSON.stringify(
        o,
        null,
        '  '
    );
});

document.getElementById('login').onclick = () => {
    const oidCallbackUrl = window.location.origin + '/auth/callback';
    const appCallbackUrl = window.location.origin + '/exampleapp/';
    const state =
        Math.random().toString(36).substring(2, 15) +
        '-appstate-' +
        Math.random().toString(36).substring(2, 15);

    sessionStorage.setItem('state', state);

    const params = new URLSearchParams({
        scope: 'openid profile email',
        redirect_uri: oidCallbackUrl,
        app_uri: appCallbackUrl,
        state,
    });

    window.location = '/auth/login?' + params.toString();
};

document.getElementById('logout').onclick = () => {
    const oidCallbackUrl = window.location.origin + '/auth/logoutcallback';
    const appCallbackUrl = window.location.origin + '/exampleapp/';

    const params = new URLSearchParams({
        redirect_uri: oidCallbackUrl,
        app_uri: appCallbackUrl,
    })
        .map(([key, value]) => key + '=' + encodeURIComponent(value))
        .join('&');

    window.location = '/auth/logout?' + params.toString();
};

document.getElementById('refresh').onclick = () => {
    fetch('/auth/refresh', {
        method: 'POST',
    })
        .then((response) => response.json())
        .then((refreshData) => console.log(refreshData));
};

document.getElementById('requestcsrftoken').onclick = () => {
    fetch('/auth/csrftoken', {
        method: 'POST',
    })
        .then((response) => response.json())
        .then((csrftokenData) => (csrftoken = csrftokenData.token));
};

document.getElementById('sso').onclick = () => {
    const oidCallbackUrl = window.location.origin + '/auth/callback';
    const appCallbackUrl = window.location.origin + '/exampleapp/sso.html';
    const state =
        Math.random().toString(36).substring(2, 15) +
        '-appstate-' +
        Math.random().toString(36).substring(2, 15);

    sessionStorage.setItem('state', state);

    const params = new URLSearchParams({
        scope: 'openid profile email',
        redirect_uri: oidCallbackUrl,
        app_uri: appCallbackUrl,
        prompt: 'none',
        state,
    });

    const iframe = createNewIframeForSSO();
    iframe.src = '/auth/login?' + params.toString();
};

document.getElementById('echorequest').onclick = () => {
    const headers = new Headers();
    headers.append('X-CSRF-TOKEN', csrftoken);
    fetch('/api/echorequest', {
        method: 'POST',
        headers,
        body: JSON.stringify({
            usermessage: document.getElementById('userinput').value,
        }),
    })
        .then((response) => response.text())
        .then((responseText) => {
            document.getElementById('echoresponse').innerText = responseText;
        });
};

document.getElementById('forwardauthrequest').onclick = () => {
    const headers = new Headers();
    headers.append('X-CSRF-TOKEN', csrftoken);
    fetch('/api/fwauth', {
        method: 'POST',
        headers,
        body: JSON.stringify({
            usermessage: document.getElementById('userinput').value,
        }),
    })
        .then((response) => response.text())
        .then((responseText) => {
            document.getElementById('echoresponse').innerText = responseText;
        });
};

const createNewIframeForSSO = () => {
    const parent = document.getElementById('ssoarea');
    while (parent.childElementCount > 0) {
        parent.removeChild(parent.childNodes[0]);
    }
    const heading = document.createElement('p');
    heading.appendChild(document.createTextNode('SSO iframe'));
    const iframe = document.createElement('iframe', {
        width: '400',
        height: '200',
    });
    parent.appendChild(heading);
    parent.appendChild(iframe);
    return iframe;
};
