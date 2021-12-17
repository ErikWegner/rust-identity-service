const ridseruri = 'http://localhost:8000/';
const client_id = 'ridser';
const redirect_uri = 'http%3A%2F%2Flocalhost%3A8030%2F/callback.html';

function getcallbackuri() {
    const state = (new Date()).getTime() + ":" + Math.random() + ":" + Math.random();
    sessionStorage.setItem('state', state);
    window.location = ridseruri + `login?client_id=${client_id}&state=${state}&redirect_uri=${redirect_uri}`;
}

function callback() {
    const params = {};
    window.location.search.split('?')[1].split('&').forEach(a => {
        const aa = a.split('=');
        params[aa[0]] = decodeURIComponent(aa[1]);
    });
    const expectedState = sessionStorage.getItem('state');
    if (expectedState != params.state) {
        console.error("State mismatch");
    }

    const formData = new FormData();
    formData.append('redirect_uri', decodeURIComponent(redirect_uri));
    formData.append('code', params.code);

    fetch(ridseruri + 'callback', {
        method: 'POST',
        body: formData
    });
}
