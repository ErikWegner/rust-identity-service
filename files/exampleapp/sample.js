const isLoggedIn = () => {
    return Promise.resolve(false);
}

isLoggedIn().then((isLoggedIn) => {
    document.getElementById('loginStatus').innerHTML = isLoggedIn ? 'authenticated' : 'not authenticated';
});

document.getElementById('login').onclick = () => {
    const scope = 'openid profile email';
    const oidCallbackUrl = window.location.origin + '/auth/callback';
    const appCallbackUrl = window.location.origin + '/exampleapp/';

    const redirectUri = encodeURIComponent(oidCallbackUrl + '?redirect_uri=' + appCallbackUrl);
    window.location = '/auth/login?scope=' + scope + '&redirect_uri=' + redirectUri;
}
