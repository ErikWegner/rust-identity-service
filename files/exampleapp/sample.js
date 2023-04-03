const isLoggedIn = () => {
    return Promise.resolve(false);
}

isLoggedIn().then((isLoggedIn) => {
    document.getElementById('loginStatus').innerHTML = isLoggedIn ? 'authenticated' : 'not authenticated';
});

document.getElementById('login').onclick = () => {
    const oidCallbackUrl = window.location.origin + '/auth/callback';
    const appCallbackUrl = window.location.origin + '/exampleapp/';

    const params = Object.entries(
        {
            scope: 'openid profile email',
            redirect_uri: oidCallbackUrl,
            app_uri: appCallbackUrl,
        }).map(([key, value]) => key + '=' + encodeURIComponent(value)).join("&");

    window.location = '/auth/login?' + params;
}
