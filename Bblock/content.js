window.onload = () => {
    const currentUrl = window.location.href;
    const allowedUrls = [
        'github.com',
        'chatgpt.com',
        'google.com',
        'arcgis.com',
        'esri.com',
        'oaiusercontent.com',
        'amap.com',
        'yuque.com',
        'kitco.com',
        'eastmoney.com',
        'alipay.com',
        'alipayobjects.com'
    ];
  
    const isAllowed = allowedUrls.some(url => currentUrl.includes(url));
  
    if (!isAllowed) {
        // 禁止跳转
        document.addEventListener('click', (e) => {
            const target = e.target.closest('a'); // 检测点击的是否是链接
            if (target) {
                e.preventDefault(); // 阻止跳转
                alert('此网站的链接跳转已被禁用');
            }
        });
  
        // 创建全屏覆盖层
        const overlay = document.createElement('div');
        overlay.style.position = 'fixed';
        overlay.style.top = '0';
        overlay.style.left = '0';
        overlay.style.width = '100vw';
        overlay.style.height = '100vh';
        overlay.style.backgroundColor = 'black';
        overlay.style.color = 'white';
        overlay.style.zIndex = '9999999';
        overlay.style.display = 'flex';
        overlay.style.flexDirection = 'column';
        overlay.style.justifyContent = 'center';
        overlay.style.alignItems = 'center';
        overlay.style.fontSize = '24px';
        overlay.style.textAlign = 'center';
        overlay.style.setProperty("background-color", "black", "important");
        overlay.style.setProperty("z-index", "9999999", "important");
  
        // 显示当前 URL
        const urlDisplay = document.createElement('div');
        urlDisplay.textContent = `当前 URL: ${currentUrl}`;
        urlDisplay.style.margin = '20px';
        overlay.appendChild(urlDisplay);
  
        // 禁用页面滚动和内容交互
        document.body.style.overflow = 'hidden';
        document.body.style.pointerEvents = 'none';
  
        // 将覆盖层添加到文档中
        document.body.appendChild(overlay);
  
        // 监视 DOM 变化以捕获动态加载的弹窗
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'childList') {
                    // 如果新节点被添加到文档中，检查是否有弹窗
                    const newNodes = mutation.addedNodes;
                    newNodes.forEach((node) => {
                        // 检查 node 是否是一个弹窗
                        if (node.nodeType === 1) { 
                            document.body.appendChild(overlay);
                        }
                    });
                }
            });
        });
  
        // 开始观察文档的变化
        observer.observe(document.body, { childList: true, subtree: true });
    } else {
        console.log('当前网址在允许的列表中，链接跳转不会被禁用。');
    }
  };
  // 禁用右键菜单
  document.addEventListener('contextmenu', (e) => {
    e.preventDefault(); // 禁止右键菜单
  });
  
  (function() {
    'use strict';
  
    // 处理链接点击事件
    document.addEventListener('click', function(event) {
        const target = event.target.closest('a'); // 检测点击的是否是链接
        if (target) {
            event.preventDefault(); // 阻止默认行为
            window.open(target.href, '_blank'); // 在新窗口打开链接
        }
    }, true); // 使用捕获阶段
  })();
  