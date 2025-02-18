function fetchLocalURLList() {
  try {
    // 添加规则，拦截所有 URL 除了允许的域名
    const blockAllRule = {
      id: 1,
      priority: 1,
      action: {
        type: 'block', // 使用字符串代替类型注解
      },
      condition: {
        urlFilter: '*://*/*', // 拦截所有域名
        resourceTypes: ['main_frame', 'sub_frame'], // 使用字符串数组
      },
    };

    // 允许访问 github.com
    const allowGithubRule = {
      id: 2,
      priority: 2,
      action: {
        type: 'allow', // 允许访问 github.com
      },
      condition: {
        urlFilter: '*://github.com/*', // 仅允许访问 github.com
        resourceTypes: ['main_frame', 'sub_frame'], // 使用字符串数组
      },
    };

    // 允许访问 127.0.0.1:* 和 localhost:*
    const allowLocalhostRule = {
      id: 3,
      priority: 3,
      action: {
        type: 'allow', // 允许访问 127.0.0.1:* 和 localhost:*
      },
      condition: {
        urlFilter: '*://127.0.0.1/*', // 允许 127.0.0.1:* 
        resourceTypes: ['main_frame', 'sub_frame'], // 使用字符串数组
      },
    };

    const allowLocalhostRule2 = {
      id: 4,
      priority: 4,
      action: {
        type: 'allow', // 允许访问 localhost:*
      },
      condition: {
        urlFilter: '*://localhost/*', // 允许 localhost:*
        resourceTypes: ['main_frame', 'sub_frame'], // 使用字符串数组
      },
    };

    // 添加屏蔽包含“firefox”的 URL 的规则
    const blockFirefoxRule = {
      id: 5,
      priority: 5,
      action: {
        type: 'block',
      },
      condition: {
        urlFilter: '*://camo.githubusercontent.com/*', // 匹配包含“firefox”的 URL
        resourceTypes: ['main_frame', 'sub_frame'], // 使用字符串数组
      },
    };

    // 更新 Chrome 动态规则
    chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [1, 2, 3, 4, 5], // 删除现有规则
      addRules: [blockAllRule, allowGithubRule, allowLocalhostRule, allowLocalhostRule2, blockFirefoxRule], // 添加新的规则
    });

    chrome.storage.local.set({ isActive: true });
  } catch (error) {
    console.error('Failed to process URL list from JS array:', error);
  }
}

// 定期刷新规则（如果列表是静态的，可以不需要）
setInterval(fetchLocalURLList, 3600000); // 每小时更新一次
fetchLocalURLList();

// 扩展安装时执行
chrome.runtime.onInstalled.addListener(() => {
  fetchLocalURLList();
});

// 监听扩展状态变化
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.isActive !== undefined) {
    const isActive = changes.isActive.newValue;
    if (!isActive) {
      chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: [1, 2, 3, 4, 5], // 删除所有现有规则
      });
    } else {
      fetchLocalURLList();
    }
  }
});
