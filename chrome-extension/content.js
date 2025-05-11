// Extract URLs from the page
function extractUrls() {
  const urls = [];
  const currentUrl = window.location.href;
  const links = document.querySelectorAll('a[href]');
  links.forEach(link => {
    const href = link.href;
    if (href.startsWith('http')) urls.push(href);
  });
  return { currentUrl, pageUrls: urls };
}

// Send URLs to background script
chrome.runtime.sendMessage({ action: 'checkUrls', data: extractUrls() });