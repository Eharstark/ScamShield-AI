/* ════════════════════════════════════════════════════════════
   ANALYZER — tab switching, file upload, mock analysis rendering
   ════════════════════════════════════════════════════════════ */

/**
 * Switch between SMS / URL / Screenshot tabs
 */
function switchTab(id, btn) {
  document.querySelectorAll('.tab').forEach((t) => {
    t.classList.remove('active');
    t.setAttribute('aria-selected', 'false');
  });
  document.querySelectorAll('.tab-panel').forEach((p) => p.classList.remove('active'));

  btn.classList.add('active');
  btn.setAttribute('aria-selected', 'true');
  document.getElementById('panel-' + id).classList.add('active');

  // Hide previous results when switching tabs
  document.getElementById('results-container').style.display = 'none';
}

/**
 * Update the SMS textarea character counter
 */
function updateCounter() {
  const len = document.getElementById('sms-input').value.length;
  document.getElementById('char-count').textContent = len;
}

/**
 * Drag-over / drag-leave visual state for the drop zone
 */
function handleDrag(e, isOver) {
  e.preventDefault();
  document.getElementById('drop-zone').classList.toggle('dragover', isOver);
}

/**
 * Handle a file dropped onto the drop zone
 */
function handleDrop(e) {
  e.preventDefault();
  handleDrag(e, false);
  const file = e.dataTransfer.files[0];
  if (file) showPreview(file);
}

/**
 * Handle a file chosen via the file input (Browse button)
 */
function handleFile(e) {
  const file = e.target.files[0];
  if (file) showPreview(file);
}

/**
 * Render an image preview from a File object
 */
function showPreview(file) {
  if (!file.type.startsWith('image/')) return;

  const reader = new FileReader();
  reader.onload = (ev) => {
    const preview = document.getElementById('img-preview');
    preview.src = ev.target.result;
    preview.style.display = 'block';
  };
  reader.readAsDataURL(file);
}

/**
 * Run a (mock) analysis for the given type: 'sms' | 'url' | 'img'
 * Animates the risk gauge and populates indicators/recommendations.
 */
async function analyze(type) {
  const resultsContainer = document.getElementById('results-container');
  resultsContainer.style.display = 'none';

  let endpoint = '';
  let options = {};

  try {
    if (type === 'sms') {
      const message = document.getElementById('sms-input').value.trim();

      if (!message) {
        alert('Please enter a suspicious SMS message.');
        return;
      }

      endpoint = '/api/analyze/sms';

      options = {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          message: message
        })
      };
    }

    else if (type === 'url') {
      const url = document.getElementById('url-input').value.trim();

      if (!url) {
        alert('Please enter a URL.');
        return;
      }

      endpoint = '/api/analyze/url';

      options = {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          url: url
        })
      };
    }

    else if (type === 'img') {
      const fileInput = document.getElementById('file-input');

      if (!fileInput.files.length) {
        alert('Please upload a screenshot.');
        return;
      }

      const formData = new FormData();
      formData.append('file', fileInput.files[0]);

      endpoint = '/api/analyze/screenshot';

      options = {
        method: 'POST',
        body: formData
      };
    }
    const response = await fetch(
      `${API_BASE_URL}${endpoint}`,
    options
);


    const data = await response.json();
console.log("Backend Response:");
console.log(data);
console.log("Calling renderResults...");

    if (!response.ok) {
      throw new Error(data.error || 'Analysis failed');
    }

    renderResults(data);

  } catch (error) {
    console.error(error);

    alert(
      error.message ||
      'Failed to connect to ScamShield AI backend.'
    );
  }
}

function renderResults(data) {

  console.log("renderResults started");
  console.log(data);

  const score = data.risk_score || 0; 

  const level = data.risk_level || 'low';

  const circumference = Math.PI * 2 * 44;
  const offset = circumference * (1 - score / 100);

  const arc = document.getElementById('gauge-arc');

  arc.style.stroke = colorMap[level];
  arc.style.strokeDashoffset = circumference;

  requestAnimationFrame(() => {
    setTimeout(() => {
      arc.style.strokeDashoffset = offset;
    }, 50);
  });

  document.getElementById('score-num').textContent =
    score + '/100';

  document.getElementById('score-num').style.color =
    colorMap[level];

  const badge = document.getElementById('risk-badge');

  badge.textContent =
    labelMap[level];

  badge.className =
    'risk-badge ' + classMap[level];

  document.getElementById('threat-cat').textContent =
    data.category || 'Unknown';

  document.getElementById('analysis-time').textContent =
    '✓ Analysis Complete';

  const indicatorsList =
    document.getElementById('indicators-list');

  indicatorsList.innerHTML =
    (data.indicators || [])
      .map(
        item => `
        <div class="indicator">
          <span class="ind-dot red"></span>
          <span>${item}</span>
        </div>
      `
      )
      .join('');

  const recsList =
    document.getElementById('recs-list');

  recsList.innerHTML =
    (data.recommendations || [])
      .map(
        (item, index) => `
        <div class="rec-item">
          <span class="rec-num">${index + 1}</span>
          <span>${item}</span>
        </div>
      `
      )
      .join('');

  document.getElementById('results-container')
    .style.display = 'block';

  document.getElementById('results-container')
    .scrollIntoView({
      behavior: 'smooth',
      block: 'nearest'
    });
}

 