const URL_LISTS = [
  'white_list.txt'
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
    const ids = [];

    ids.push(1);
    const rule = {
      id: 1,
      action: {
        type: 'redirect',
        redirect: {
          extensionPath: '/blocked.html' 
        }
      },
      condition: {
        regexFilter: '^http',
        resourceTypes: ['main_frame', 'sub_frame'],
        isUrlFilterCaseSensitive: false
      }
    };
    
    // 使用 Set 来存储已占用的 ID
  const usedIds = new Set(ids);

  // 定义一个函数来找到下一个未被占用的 ID
  const getNextAvailableId = () => {
    let id = 1; // 从 1 开始
    // 找到第一个未被占用的 ID
    while (usedIds.has(id)) {
      id += 1; // 找到下一个未占用的 ID
    }
    usedIds.add(id); // 将找到的 ID 添加到已使用的 ID 列表中
    return id; // 返回找到的 ID
  };

  // 生成规则集合的 ID 列表
  const rules = data.map((url) => {
    const id = getNextAvailableId(); // 获取下一个可用的 ID

    return {
      id: id, // 使用生成的 ID
      priority: 1,
      action: { type: 'allow' },
      condition: {
        urlFilter: url,
        resourceTypes: ['main_frame', 'sub_frame']
      }
    };
  });

  // 为 Google 搜索规则生成一个新的 ID
  const googleSearchRuleId = getNextAvailableId(); // 获取下一个可用的 ID

  // 使用动态生成的 ID 创建 googleSearchRule
  const googleSearchRule = {
    id: googleSearchRuleId, // 使用生成的 ID
    priority: 1,
    action: { type: 'redirect', redirect: { extensionPath: '/blocked.html' } },
    condition: {
      urlFilter: '*://www.google.com/search*',
      resourceTypes: ['main_frame']
    }
  };

  // 添加到规则列表
  rules.push(googleSearchRule);



    chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: rules.map(rule => rule.id),
      addRules: [rule,...rules]
    });

    chrome.storage.local.set({ isActive: true });
  } catch (error) {
    console.error('Failed to fetch URL list:', error);
  }
}
  // Update the list of URLs periodically
  setInterval(fetchURLList, 600000); // Update every 1 hour
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
