/* Login page behavior: theme toggle, password eye, carousel dots, ambient
   canvas. External on purpose: the CSP is script-src 'self', so the former
   inline <script> block and the onclick= attributes silently never ran — the
   dark-mode button did nothing. Buttons are bound with addEventListener here. */

/* ── Password eye toggle ── */
function sentroEyeToggle() {
  var input = document.getElementById('login-password');
  var eyeA  = document.getElementById('eyeA');
  var eyeB  = document.getElementById('eyeB');
  if (!input || !eyeA || !eyeB) return;
  var nowVisible = input.type === 'text';
  input.type         = nowVisible ? 'password' : 'text';
  // A class, not style.display: login.css hides the second icon until it is wanted (C6).
  // Revealed: the slashed eye offers to hide it again; hidden: the open eye offers to show it.
  eyeA.classList.toggle('is-hidden', !nowVisible);
  eyeB.classList.toggle('is-hidden', nowVisible);
}

/* ── Theme toggle ── */
function sentroThemeToggle() {
  var root  = document.documentElement;
  var icon  = document.querySelector('#themeBtn .theme-icon');
  var dark  = root.getAttribute('data-theme') === 'dark';
  var next  = dark ? 'light' : 'dark';
  root.setAttribute('data-theme', next);
  if (icon) icon.innerHTML = next === 'dark' ? '&#9728;' : '&#9790;';
  try { localStorage.setItem('dspm-theme', next); } catch (e) {}
}

(function () {
  var themeBtn = document.getElementById('themeBtn');
  var eyeBtn = document.getElementById('eyeBtn');
  if (themeBtn) themeBtn.addEventListener('click', sentroThemeToggle);
  if (eyeBtn) eyeBtn.addEventListener('click', sentroEyeToggle);

  /* Sync button icon to whatever theme auth-boot.js restored */
  var t = document.documentElement.getAttribute('data-theme');
  var icon = document.querySelector('#themeBtn .theme-icon');
  if (icon) icon.innerHTML = t === 'dark' ? '&#9728;' : '&#9790;';
})();

/* ── Carousel dots ── */
(function () {
  var dots = document.querySelectorAll('#dotsEl .dot');
  if (!dots.length) return;
  var di = 0;
  setInterval(function () {
    dots[di].classList.remove('on');
    di = (di + 1) % dots.length;
    dots[di].classList.add('on');
  }, 4000);
})();

/* ── Ambient canvas (static frame under prefers-reduced-motion) ── */
(function () {
  var cv  = document.getElementById('cvs');
  if (!cv) return;
  var ctx2 = cv.getContext('2d');
  var W = 0, H = 0, tick = 0;
  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  var pts = Array.from({ length: 30 }, function () {
    return {
      x: Math.random(), y: Math.random(),
      vx: (Math.random() - .5) * .00016, vy: (Math.random() - .5) * .00016,
      r: 1.2 + Math.random() * 2, d: Math.random(), ph: Math.random() * Math.PI * 2,
    };
  });

  function resize() {
    var p = cv.parentElement;
    W = p.offsetWidth; H = p.offsetHeight;
    cv.width = W; cv.height = H;
  }

  function draw() {
    var dark = document.documentElement.getAttribute('data-theme') === 'dark';
    if (dark) { ctx2.fillStyle = '#060914'; ctx2.fillRect(0, 0, W, H); }
    else ctx2.clearRect(0, 0, W, H);

    tick++;
    pts.forEach(function (p) {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0 || p.x > 1) p.vx *= -1;
      if (p.y < 0 || p.y > 1) p.vy *= -1;
    });

    var la = dark ? .1 : .07;
    for (var i = 0; i < pts.length; i++) {
      for (var j = i + 1; j < pts.length; j++) {
        var a = pts[i], b = pts[j];
        var dx = (a.x - b.x) * W, dy = (a.y - b.y) * H;
        var dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 185) {
          ctx2.strokeStyle = 'rgba(255,255,255,' + ((1 - dist / 185) * la) + ')';
          ctx2.lineWidth = .5;
          ctx2.beginPath(); ctx2.moveTo(a.x * W, a.y * H); ctx2.lineTo(b.x * W, b.y * H); ctx2.stroke();
        }
      }
    }

    pts.forEach(function (p) {
      var cx = p.x * W, cy = p.y * H;
      var pulse = .6 + .4 * Math.sin(tick * .016 + p.ph);
      var al = (.18 + .28 * p.d) * pulse;
      ctx2.fillStyle = 'rgba(255,255,255,' + (al * .18) + ')';
      ctx2.beginPath(); ctx2.arc(cx, cy, p.r * 5, 0, Math.PI * 2); ctx2.fill();
      ctx2.fillStyle = 'rgba(255,255,255,' + al + ')';
      ctx2.beginPath(); ctx2.arc(cx, cy, p.r, 0, Math.PI * 2); ctx2.fill();
    });

    if (!reduceMotion) requestAnimationFrame(draw);
  }

  new ResizeObserver(resize).observe(cv.parentElement);
  resize();
  draw();
})();
