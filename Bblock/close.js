setTimeout(() => {
  window.close();
  chrome.runtime.sendMessage({
    method: 'close-page'
  }, () => chrome.runtime.lastError);
}, 30000); // 30000 毫秒 = 30 秒
