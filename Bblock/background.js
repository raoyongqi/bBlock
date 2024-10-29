const URL_LISTS = [
  'categoryporn.txt','blacklist.txt','search.txt'
  ];

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

    const normalizedData = data.map(url => {
      if (url.includes('google')) {
        return [`*://${url}/search*`]; // 返回特定格式
      }
      if (!url.startsWith('http://') && !url.startsWith('https://')) {

        return [`*://${url}/*`, `*://*.${url}/*`]; // 返回其他格式
      }
      return url;
    });
    
    const flatNormalizedData = [].concat(...normalizedData);

    const rules = flatNormalizedData.map((url, index) => ({
      id: index + 1,
      priority: 1,
      action: { type: 'redirect', redirect: { extensionPath: '/blocked.html' } },
      condition: {
        urlFilter: url,
        resourceTypes: ["main_frame"]
      }
    }));

    const googleSearchRule = {
      id: 500, // 规则 ID
      priority: 1,
      action: { type: 'redirect', redirect: { extensionPath: '/blocked.html' } },
      condition: {
        urlFilter: '*://www.google.com/search*', // 屏蔽 google.com 的搜索子网址
        resourceTypes: ['main_frame'] // 只针对主框架的请求
      }
    };
    rules.push(googleSearchRule);


    chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: rules.map(rule => rule.id),
      addRules: rules
    });

    chrome.storage.local.set({ isActive: true });
  } catch (error) {
    console.error('Failed to fetch URL list:', error);
  }
}
  // Update the list of URLs periodically
  setInterval(fetchURLList, 6000); // Update every 1 hour
  fetchURLList();
  
  chrome.runtime.onInstalled.addListener(() => {
    fetchURLList();
  });
  
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes.isActive !== undefined) {
      const isActive = changes.isActive.newValue;
      if (!isActive) {
        chrome.declarativeNetRequest.getDynamicRules((rules) => {
          // 提取所有规则的 ID
          const ruleIds = rules.map(rule => rule.id);
          
          // 移除所有规则
          chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: ruleIds // 移除所有规则
          });
        });
      } else {
        fetchURLList();
      }
    }
  });
