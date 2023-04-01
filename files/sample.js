const isLoggedIn = () => {
    return Promise.resolve(false);
}

isLoggedIn().then((isLoggedIn) => {
    document.getElementById('loginStatus').innerHTML = isLoggedIn ? 'authenticated' : 'not authenticated';
});
