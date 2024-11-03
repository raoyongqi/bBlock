const URL_LISTS = [
  'whitelist.txt'
];

const convert = (h = '') => {
  if (!h.startsWith('R:')) {
    if (!h.includes('://') && !h.includes('*')) {
      return `^https*:\\/\\/([^/]+\\.)*` + convert.escape(h);
    } else {
      return '^' + h.split('*').map(convert.escape).join('.*');
    }
  }
  if (h.startsWith('R:^')) {
    return h.substr(2);
  }
  return '^.*' + h.substr(2);
};

convert.escape = str => {
  const specials = [
    '-', '[', ']', '/', '{', '}', '(', ')', '*', '+', '?', '.', '\\', '^', '$', '|'
  ];
  const regex = RegExp('[' + specials.join('\\') + ']', 'g');
  return str.replace(regex, '\\$&');
};

async function fetchURLList() {
  try {
    const responses = await Promise.all(URL_LISTS.map(url =>
      fetch(url).catch(err => {
        console.error('Fetch error for URL:', url, err);
        return { ok: false, url };
      })
    ));

    const texts = await Promise.all(responses.map(response => {
      if (!response.ok) {
        console.error(`Network response was not ok for ${response.url}`);
        return '';
      }
      return response.text();
    }));

    const data = texts.flatMap(text =>
      text.split('\n')
          .filter(line => line && !line.startsWith('!') && !line.startsWith('['))
          .map(url => url.trim())
    );

    // Store URL patterns
    await browser.storage.local.set({ urlPatterns: data });

    // Initialize rules
    initializeWebRequestRules(data);
  } catch (error) {
    console.error('Failed to fetch URL list:', error);
  }
}

function initializeWebRequestRules(urlPatterns) {
  browser.webRequest.onBeforeRequest.addListener(
    (details) => {
      const url = details.url;

      // Check for Google Search URL
      if (url.includes('www.google.com/search')) {
        return { redirectUrl: browser.runtime.getURL('/blocked.html') }; // Redirect 
      }

      // Match against the patterns from storage
      const isAllowed = urlPatterns.some(pattern => new RegExp(convert(pattern)).test(url));
      return isAllowed ? { cancel: false } : { redirectUrl: browser.runtime.getURL('/blocked.html') }; 
    },
    { urls: ["<all_urls>"] }, // Apply to all URLs
    ["blocking"]
  );
}

// Initialize and listen to updates
browser.runtime.onInstalled.addListener(() => {
  fetchURLList();
});

browser.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.isActive !== undefined) {
    const isActive = changes.isActive.newValue;
    if (!isActive) {
      // If inactive, remove listener or take necessary actions
      browser.webRequest.onBeforeRequest.removeListener(initializeWebRequestRules);
    } else {
      fetchURLList();
    }
  }
});
