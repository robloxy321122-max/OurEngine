const menuToggle = document.getElementById('menuToggle');
const nav = document.getElementById('nav');
menuToggle.addEventListener('click', () => {
  const isOpen = nav.classList.toggle('open');
  menuToggle.setAttribute('aria-expanded', String(isOpen));
});
nav.querySelectorAll('a').forEach(link => link.addEventListener('click', () => {
  nav.classList.remove('open');
  menuToggle.setAttribute('aria-expanded', 'false');
}));
document.getElementById('year').textContent = new Date().getFullYear();

const message = document.getElementById('authMessage');
const signIn = document.getElementById('discordSignIn');
const discordNav = document.getElementById('discordNav');
const signedIn = document.getElementById('signedIn');

async function loadSession() {
  const params = new URLSearchParams(location.search);
  if (params.get('error') === 'oauth') {
    message.textContent = 'Discord sign-in did not complete. Please try again.';
    history.replaceState({}, '', location.pathname);
  }
  try {
    const response = await fetch('/api/auth/me', { credentials: 'same-origin' });
    if (!response.ok) return;
    const data = await response.json();
    if (!data.user) return;
    document.getElementById('username').textContent =
      data.user.global_name || data.user.username;
    const avatar = document.getElementById('avatar');
    if (data.user.avatar) {
      avatar.src = `https://cdn.discordapp.com/avatars/${data.user.id}/${data.user.avatar}.png?size=64`;
    } else {
      avatar.src = 'https://cdn.discordapp.com/embed/avatars/0.png';
    }
    signedIn.hidden = false;
    signIn.hidden = true;
    discordNav.textContent = 'Signed in';
    discordNav.href = '#get-started';
  } catch (_) {
    message.textContent = 'Could not check your sign-in status. Refresh and try again.';
  }
}
document.getElementById('signOut').addEventListener('click', async () => {
  await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' });
  location.href = '/';
});
loadSession();
