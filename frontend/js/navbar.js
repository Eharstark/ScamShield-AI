/* ════════════════════════════════════════════════════════════
   NAVBAR — mobile menu toggle + smooth-scroll close on link click
   ════════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {
  const hamburger = document.getElementById('hamburger');
  const navLinks = document.getElementById('nav-links');

  if (!hamburger || !navLinks) return;

  hamburger.addEventListener('click', () => {
    const isOpen = navLinks.classList.toggle('open');
    hamburger.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    hamburger.innerHTML = isOpen
      ? '<i class="ti ti-x" aria-hidden="true"></i>'
      : '<i class="ti ti-menu-2" aria-hidden="true"></i>';
  });

  // Close mobile menu after tapping a link
  navLinks.querySelectorAll('a').forEach((link) => {
    link.addEventListener('click', () => {
      navLinks.classList.remove('open');
      hamburger.setAttribute('aria-expanded', 'false');
      hamburger.innerHTML = '<i class="ti ti-menu-2" aria-hidden="true"></i>';
    });
  });
});
