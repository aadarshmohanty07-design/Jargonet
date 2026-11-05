'use strict';

// The only external dependency is the version-pinned asciinema player. It is
// loaded lazily when the demo section approaches the viewport, so a normal
// page visit makes no third-party requests.
const PLAYER = {
  version: '3.10.0',
  base: 'https://cdn.jsdelivr.net/npm/asciinema-player@3.10.0/dist/bundle/',
  cssIntegrity: 'sha384-ip3FNCEWlvYiQekhiNJajkdjXmMnJGL4h5RE+8xkdUqUHdvUjpKIp0knqeEHrJa8',
  jsIntegrity: 'sha384-ZbdjWnVijNdYH2Zm/9OoOQ9113NHMeF+lgJRN6kPFlw+y2dXswRObxFbNSTTymc1'
};

const demoSection = document.getElementById('demo');
const playerHost = document.getElementById('asciinema-player');
const playerStatus = document.getElementById('player-status');
const playerFallback = document.getElementById('player-fallback');
const castUrl = playerHost ? playerHost.dataset.cast || './assets/demo.cast' : './assets/demo.cast';

let playerRequested = false;

function loadStylesheet() {
  return new Promise((resolve, reject) => {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = `${PLAYER.base}asciinema-player.css`;
    link.integrity = PLAYER.cssIntegrity;
    link.crossOrigin = 'anonymous';
    link.referrerPolicy = 'no-referrer';
    link.onload = () => resolve();
    link.onerror = () => reject(new Error('player stylesheet failed'));
    document.head.appendChild(link);
  });
}

function loadScript() {
  return new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = `${PLAYER.base}asciinema-player.min.js`;
    script.integrity = PLAYER.jsIntegrity;
    script.crossOrigin = 'anonymous';
    script.referrerPolicy = 'no-referrer';
    script.onload = () => resolve();
    script.onerror = () => reject(new Error('player script failed'));
    document.head.appendChild(script);
  });
}

function showFallback(message) {
  if (playerStatus) playerStatus.hidden = true;
  if (playerHost) playerHost.hidden = true;
  if (!playerFallback) return;
  playerFallback.hidden = false;
  playerFallback.innerHTML = message;
}

async function initPlayer() {
  if (playerRequested || !playerHost) return;
  playerRequested = true;

  if (location.protocol === 'file:') {
    showFallback('The recording is available on the live site. Opening this page from disk blocks the local cast fetch; use a local HTTP server to preview it. The command sequence is in the <a href="https://github.com/aadarshmohanty07-design/Jargonet/blob/main/meshchat/DEMO.md" target="_blank" rel="noopener noreferrer">runbook</a>.');
    return;
  }

  try {
    const response = await fetch(castUrl, { cache: 'no-store' });
    if (!response.ok) throw new Error('cast missing');
    const cast = await response.text();
    if (!cast.trim() || cast.includes('PLACEHOLDER')) {
      showFallback('Demo recording will be added before submission. The exact command sequence is in the <a href="https://github.com/aadarshmohanty07-design/Jargonet/blob/main/meshchat/DEMO.md" target="_blank" rel="noopener noreferrer">runbook</a>.');
      return;
    }

    await loadStylesheet();
    await loadScript();
    if (!window.AsciinemaPlayer) throw new Error('player API missing');

    if (playerStatus) playerStatus.hidden = true;
    window.AsciinemaPlayer.create(castUrl, playerHost, {
      autoPlay: false,
      loop: false,
      speed: 1,
      fit: 'width',
      theme: 'monokai'
    });
  } catch (error) {
    showFallback('The terminal recording could not load here. The exact command sequence is in the <a href="https://github.com/aadarshmohanty07-design/Jargonet/blob/main/meshchat/DEMO.md" target="_blank" rel="noopener noreferrer">runbook</a>.');
  }
}

function initDemoLoader() {
  if (!demoSection) return;

  const revealDemo = () => initPlayer();
  document.querySelectorAll('a[href="#demo"]').forEach((link) => {
    link.addEventListener('click', revealDemo);
  });

  if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver((entries) => {
      if (entries.some((entry) => entry.isIntersecting)) {
        observer.disconnect();
        initPlayer();
      }
    }, { rootMargin: '320px 0px' });
    observer.observe(demoSection);
  } else {
    initPlayer();
  }
}

function initReveal() {
  const sections = Array.from(document.querySelectorAll('main > section'))
    .filter((section) => !section.classList.contains('hero'));
  if (!sections.length) return;

  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduceMotion || !('IntersectionObserver' in window)) return;

  sections.forEach((section) => section.classList.add('will-reveal'));
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting) return;
      entry.target.classList.add('is-visible');
      observer.unobserve(entry.target);
    });
  }, { threshold: 0.08 });
  sections.forEach((section) => observer.observe(section));
}

async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const field = document.createElement('textarea');
  field.value = text;
  field.setAttribute('readonly', '');
  field.style.position = 'fixed';
  field.style.left = '-9999px';
  document.body.appendChild(field);
  field.select();
  const ok = document.execCommand('copy');
  field.remove();
  if (!ok) throw new Error('copy failed');
}

function initCopyButtons() {
  document.querySelectorAll('.copy').forEach((button) => {
    button.addEventListener('click', async () => {
      const target = document.getElementById(button.dataset.copyTarget);
      if (!target) return;
      const original = button.textContent;
      try {
        await copyText(target.innerText);
        button.textContent = 'Copied';
      } catch (error) {
        button.textContent = 'Select';
        window.getSelection().selectAllChildren(target);
      }
      setTimeout(() => { button.textContent = original; }, 1600);
    });
  });
}

initDemoLoader();
initReveal();
initCopyButtons();
