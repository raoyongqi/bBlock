const URL_LISTS = [
  'whitelist.txt'
  ];
  const convert = (h = '') => {
    if (h.startsWith('R:') === false) {
      if (h.indexOf('://') === -1 && h.indexOf('*') === -1) {
        return `^https*:\\/\\/([^/]+\\.)*` + convert.escape(h);
      }
      else {
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
      // order matters for these
      '-', '[', ']',
      // order doesn't matter for any of these
      '/', '{', '}', '(', ')', '*', '+', '?', '.', '\\', '^', '$', '|'
    ];
    const regex = RegExp('[' + specials.join('\\') + ']', 'g');
    return str.replace(regex, '\\$&');
  };

// 初始化已使用的 ID 集合
const usedIds = new Set();

const getNextAvailableId = () => {
  let id = 1;
  while (usedIds.has(id)) {
    id += 1;
  }
  usedIds.add(id);
  return id;
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

    const currentRules = await chrome.declarativeNetRequest.getDynamicRules();
    const ruleIds = currentRules.map(rule => rule.id);

    // 清除现有规则并更新已使用的 ID 集合
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: ruleIds
    });
    ruleIds.forEach(id => usedIds.delete(id));

    // 初始重定向规则
    const initialRule = {
      id: getNextAvailableId(),
      action: {
        type: 'redirect',
        redirect: {
          regexSubstitution: chrome.runtime.getURL('/blocked.html') + '?url=\\0'
        }
      },
      condition: {
        regexFilter: '^http',
        resourceTypes: ['main_frame', 'sub_frame'],
        isUrlFilterCaseSensitive: false
      }
    };

    await chrome.declarativeNetRequest.updateDynamicRules({
      addRules: [initialRule]
    });

    // 逐一添加数据中的规则
    for (const url of data) {
      const newRule = {
        id: getNextAvailableId(),
        priority: 1,
        action: { type: 'allow' },
        condition: {
          regexFilter: convert(url),
          isUrlFilterCaseSensitive: false,
          resourceTypes: ['main_frame', 'sub_frame']
        }
      };
      await chrome.declarativeNetRequest.updateDynamicRules({
        addRules: [newRule]
      });
    }

    // 添加 Google Search 规则
    const googleSearchRule = {
      id: getNextAvailableId(),
      priority: 1,
      action: { type: 'redirect', redirect: { extensionPath: '/blocked.html' } },
      condition: {
        urlFilter: '*://www.google.com/search*',
        resourceTypes: ['main_frame']
      }
    };
    await chrome.declarativeNetRequest.updateDynamicRules({
      addRules: [googleSearchRule]
    });

    // 添加 Firefox 下载规则
    const firefoxDownloadRule = {
      id: getNextAvailableId(),
      priority: 1,
      action: { type: 'redirect', redirect: { extensionPath: '/blocked.html' } },
      condition: {
        regexFilter: '.*firefox.*',
        resourceTypes: ['main_frame', 'sub_frame'],
        isUrlFilterCaseSensitive: false
      }
    };
    await chrome.declarativeNetRequest.updateDynamicRules({
      addRules: [firefoxDownloadRule]
    });

    chrome.storage.local.set({ isActive: true });
  } catch (error) {
    console.error('Failed to fetch URL list:', error);
  }
}

  // Update the list of URLs periodically
setInterval(fetchURLList, 3600000); // Update every 1 hour

// Initialize and listen to updates
chrome.runtime.onInstalled.addListener(() => {
  fetchURLList();
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.isActive !== undefined) {
    const isActive = changes.isActive.newValue;
    if (!isActive) {
      chrome.declarativeNetRequest.getDynamicRules((rules) => {
        const ruleIds = rules.map(rule => rule.id);
        chrome.declarativeNetRequest.updateDynamicRules({
          removeRuleIds: ruleIds
        });
      });
    } else {
      fetchURLList();
    }
  }
});
