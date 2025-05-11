chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'checkUrls') {
    const { currentUrl, pageUrls } = message.data;
    const apiUrl = 'https://phising-detection-l47v.onrender.com'; // Replace with your API URL

    // Check current URL
    fetch(apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: currentUrl })
    })
      .then(res => res.json())
      .then(currentResult => {
        // Check page links (limit to avoid overwhelming the server)
        const linkPromises = pageUrls.slice(0, 10).map(url =>
          fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: currentUrl })
          }).then(res => res.json())
        );

        Promise.all(linkPromises).then(linkResults => {
          const suspiciousLinks = linkResults
            .filter(result => !result.error)
            .map(result => ({
              url: result.url,
              result: result.result,
              confidence: result.confidence
            }));

          // Store results for popup
          chrome.storage.local.set({
            currentUrl,
            currentResult,
            suspiciousLinks
          });

          // Update badge with suspicious link count
          chrome.action.setBadgeText({ text: suspiciousLinks.length.toString() });
          chrome.action.setBadgeBackgroundColor({ color: '#FF0000' });
        });
      })
      .catch(error => {
        chrome.storage.local.set({
          error: 'Failed to connect to server'
        });
      });
  } else if (message.action === 'getResults') {
    chrome.storage.local.get(['currentUrl', 'currentResult', 'suspiciousLinks', 'error'], (data) => {
      sendResponse(data);
    });
    return true; // Keep the message channel open for async response
  }
});