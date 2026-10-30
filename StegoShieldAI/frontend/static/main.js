/* ==========================================================================
   STEGOSHIELD AI - INTERACTIVE JAVASCRIPT & ANIMATIONS
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
  console.log("StegoShield AI Platform script initialized.");

  // 1. Binary Stream Canvas Backdrop Animation
  const canvas = document.getElementById('binaryCanvas');
  if (canvas) {
    const ctx = canvas.getContext('2d');

    function resizeCanvas() {
      canvas.width = canvas.parentElement.offsetWidth;
      canvas.height = canvas.parentElement.offsetHeight;
    }
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    const chars = '01';
    const fontSize = 14;
    const columns = Math.floor(canvas.width / fontSize);
    const drops = Array(columns).fill(1);

    function drawMatrix() {
      ctx.fillStyle = 'rgba(255, 255, 255, 0.08)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      ctx.fillStyle = '#1d4ed8';
      ctx.font = `${fontSize}px 'JetBrains Mono', monospace`;

      for (let i = 0; i < drops.length; i++) {
        const text = chars[Math.floor(Math.random() * chars.length)];
        ctx.fillText(text, i * fontSize, drops[i] * fontSize);

        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
          drops[i] = 0;
        }
        drops[i]++;
      }
    }

    setInterval(drawMatrix, 50);
  }

  // 2. Interactive LSB Bit-Flip Animation Widget
  const lsbBitBox = document.getElementById('lsbBitTarget');
  if (lsbBitBox) {
    let flipped = false;
    setInterval(() => {
      flipped = !flipped;
      if (flipped) {
        lsbBitBox.innerText = '1';
        lsbBitBox.classList.add('lsb-flipped');
      } else {
        lsbBitBox.innerText = '0';
        lsbBitBox.classList.remove('lsb-flipped');
      }
    }, 1800);
  }

  // 3. File Upload Dropzone Auto-Update
  const fileInputs = document.querySelectorAll('input[type="file"]');
  fileInputs.forEach(input => {
    input.addEventListener('change', (e) => {
      const fileName = e.target.files[0]?.name;
      const box = input.closest('.file-upload-box');
      if (box && fileName) {
        const textElement = box.querySelector('.upload-text');
        if (textElement) {
          textElement.innerHTML = `<strong>Selected File:</strong> <span style="color: var(--accent-blue);">${fileName}</span>`;
        }
      }
    });
  });

  // 4. Real-Time Capacity Checker API Trigger
  const capForm = document.getElementById('capacityForm');
  if (capForm) {
    const fileInput = capForm.querySelector('input[type="file"]');
    const secretInput = capForm.querySelector('input[name="secret_size"]');

    function triggerCapacityCheck() {
      if (!fileInput || !fileInput.files[0]) return;

      const formData = new FormData();
      formData.append('file', fileInput.files[0]);
      formData.append('secret_bytes', secretInput ? secretInput.value : 0);

      fetch('/api/capacity', {
        method: 'POST',
        body: formData
      })
      .then(res => res.json())
      .then(data => {
        if (data.error) return;
        const resBox = document.getElementById('capacityApiResult');
        if (resBox) {
          resBox.style.display = 'block';
          resBox.innerHTML = `
            <div class="card card-blue" style="margin-top: 1.5rem; background: #f8fafc;">
              <h3 style="color: #0f172a; margin-bottom: 1rem;">📊 Capacity Analysis Summary</h3>
              <div class="grid-3">
                <div class="metric-box">
                  <div class="metric-value">${data.file_size_formatted}</div>
                  <div class="metric-label">Cover File Size</div>
                </div>
                <div class="metric-box">
                  <div class="metric-value" style="color: var(--accent-emerald);">${data.max_payload_formatted}</div>
                  <div class="metric-label">Max Hidden Capacity</div>
                </div>
                <div class="metric-box">
                  <div class="metric-value" style="color: ${data.is_supported ? '#059669' : '#dc2626'};">${data.status}</div>
                  <div class="metric-label">Validation Status</div>
                </div>
              </div>
            </div>
          `;
        }
      })
      .catch(err => console.error("Capacity API error:", err));
    }

    if (fileInput) fileInput.addEventListener('change', triggerCapacityCheck);
    if (secretInput) secretInput.addEventListener('input', triggerCapacityCheck);
  }

  const navToggle = document.getElementById('navToggle');
  const primaryNav = document.getElementById('primaryNav');
  if (navToggle && primaryNav) {
    navToggle.addEventListener('click', () => {
      const open = primaryNav.classList.toggle('open');
      navToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
  }

  document.querySelectorAll('.nav-item').forEach((item) => {
    const trigger = item.querySelector(':scope > .nav-link');
    const menu = item.querySelector('.dropdown-menu');
    if (!trigger || !menu) return;
    trigger.addEventListener('click', (event) => {
      if (window.innerWidth > 900) return;
      event.preventDefault();
      item.classList.toggle('open');
    });
  });

  const overlay = document.getElementById('jobOverlay');
  const overlayText = document.getElementById('jobOverlayText');
  document.querySelectorAll('form.js-job-form').forEach((form) => {
    form.addEventListener('submit', () => {
      if (overlay) {
        overlay.hidden = false;
        if (overlayText) {
          overlayText.textContent = form.dataset.busyMessage || 'Working…';
        }
      }
      form.querySelectorAll('button[type="submit"]').forEach((btn) => {
        btn.disabled = true;
      });
    });
  });

  document.querySelectorAll('.vault-item').forEach((item) => {
    const hidden = item.querySelector('.vault-secret-value');
    const display = item.querySelector('.vault-secret-display');
    const revealBtn = item.querySelector('.vault-reveal');
    const copyBtn = item.querySelector('.vault-copy');
    if (!hidden || !display) return;

    if (revealBtn) {
      revealBtn.addEventListener('click', () => {
        const showing = revealBtn.dataset.revealed === '1';
        if (showing) {
          display.textContent = '••••••••';
          revealBtn.dataset.revealed = '0';
          revealBtn.textContent = 'Reveal';
        } else {
          display.textContent = hidden.value;
          revealBtn.dataset.revealed = '1';
          revealBtn.textContent = 'Hide';
        }
      });
    }

    if (copyBtn) {
      copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(hidden.value).then(() => {
          copyBtn.textContent = 'Copied';
          setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1200);
        });
      });
    }
  });
});

// Copy Text Helper Function
function copyToClipboard(elementId) {
  const element = document.getElementById(elementId);
  if (element) {
    const text = element.innerText || element.value;
    navigator.clipboard.writeText(text).then(() => {
      alert("✅ Text copied to clipboard!");
    }).catch(err => {
      console.error("Clipboard copy failed:", err);
    });
  }
}
