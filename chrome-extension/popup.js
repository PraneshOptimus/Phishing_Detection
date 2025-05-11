document.addEventListener('DOMContentLoaded', () => {
  chrome.runtime.sendMessage({ action: 'getResults' }, (response) => {
    if (response.error) {
      document.getElementById('status').textContent = 'Error: ' + response.error;
      return;
    }

    // Display current URL result
    document.getElementById('current-url').textContent = response.currentUrl;
    document.getElementById('status').textContent = 
      response.currentResult.result === 'phishing' 
        ? `⚠️ Phishing Detected (${(response.currentResult.confidence * 100).toFixed(2)}%)` 
        : `Safe (${(response.currentResult.confidence * 100).toFixed(2)}%)`;

    // Display suspicious links
    const linkList = document.getElementById('link-results');
    response.suspiciousLinks.forEach(link => {
      const li = document.createElement('li');
      li.textContent = `${link.url}: ${link.result} (${(link.confidence * 100).toFixed(2)}%)`;
      if (link.result === 'phishing') li.style.color = 'red';
      linkList.appendChild(li);
    });

    // Report false positive
    document.getElementById('report').addEventListener('click', () => {
      fetch('https://phising-detection-l47v.onrender.com/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: response.currentUrl, result: response.currentResult })
      }).then(() => alert('Feedback sent!'));
    });
  });
});