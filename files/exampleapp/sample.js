const isLoggedIn = () => fetch('/auth/status').then(response => response.json());

isLoggedIn().then((isLoggedInData) => {
    document.getElementById('loginStatus').innerHTML = isLoggedInData.authenticated ? `authenticated (exp: ${isLoggedInData.expires_in}, refexp: ${isLoggedInData.refresh_expires_in})` : 'not authenticated';
});

document.getElementById('login').onclick = () => {
    const oidCallbackUrl = window.location.origin + '/auth/callback';
    const appCallbackUrl = window.location.origin + '/exampleapp/';
    const state = Math.random().toString(36).substring(2, 15) + '-appstate-' + Math.random().toString(36).substring(2, 15);

    sessionStorage.setItem('state', state);

    const params = Object.entries(
        {
            scope: 'openid profile email',
            redirect_uri: oidCallbackUrl,
            app_uri: appCallbackUrl,
            state
        }).map(([key, value]) => key + '=' + encodeURIComponent(value)).join("&");

    window.location = '/auth/login?' + params;
}
