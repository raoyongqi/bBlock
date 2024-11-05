const allowedUrls = [
    "reproducible-builds.org",
    "chatgpt.com",
    "github.com",
    "code.earthengine.google.com",
    "diver.google.com",
    "google.com",
    "*.google.com",
    "arcgis.com",
    "*.esri.com",
    "strongvpn.com",
    "*.strongvpn.com",
    "kimi.com",
    "*.oaiusercontent.com",
    "*.amap.com",
    "yuque.com",
    "eastmoney.com",
    "kitco.com",
    "alipay.com",
    "alipayobjects.com",
    "cnki.net",
    "*.cnki.net",
    "doi.org",
    "*.elsevier.com",
    "elsevier.com",
    "mdpi.com",
    "ngcc.cn",
    "nwr.gov.cn",
    "tianditu.gov.cn",
    "gee-community-catalog.org",
    "wiley.com",
    "*.wiley.com",
    "osgeo.org",
    "*.osgeo.org",
    "*.readthedocs.io",
    "mercurial-scm.org",
    "openai.com",
    "*.openai.com",
    "*.chatgpt.com",
    "cloudflare.com",
    "live.com",
    "*.live.com",
    "mail.qq.com",
    "*.mail.qq.com",
    "*.weixin.qq.com",
    "graph.qq.com",
    "imgcache.qq.com",
    "webextension.org",
    "*.ptlogin2.qq.com",
    "*.captcha.qq.com",
    "captcha.gtimg.com",
    "flickerfree.org",
    "passmark.com",
    "python.org",
    "*.microsoft.com",
    "rustup.rs",
    "*.githubusercontent.com",
    "*.qqmail.com",
    "*.oaistatic.com"
  ];
  
  const blockedUrls = [
    "*://www.google.com/search*",
    ".*firefox.*",// 添加一个用于阻止包含“firefox”的 URL 的正则表达式
    ".*firefox" // 添加一个用于阻止包含“firefox”的 URL 的正则表达式
  ];
  
  // 测试的 URL 列表
const testUrls = [
    "https://www.mozilla.org/en-US/firefox/new/",
    "https://github.com/search?type=repositories&q=firefox",
    "https://www.google.com/search",
    "https://github.com/search?q=firefox&type=repositories",
    "https://www.osgeo.org/projects/torchgeo/",
    "https://www.cnki.net/",
    "https://kns.cnki.net/kcms2/article"
  ];
  
  // 遍历 URL 并检查是否被阻止
  testUrls.forEach(url => {
    const isBlocked = blockedUrls.some(pattern => {
      const regex = new RegExp(pattern.replace(/\*/g, '.*'));
      return regex.test(url);
    });
  
    if (isBlocked) {
      console.log(`URL: ${url} -> block by isBlocked`);
    } else {
      const host = new URL(url).hostname;
      const isAllowed = allowedUrls.some(pattern => {
        if (pattern.startsWith("*.") && host.endsWith(pattern.slice(2))) {
          return true;
        }
        return host === pattern || host === 'www.' + pattern;
      });
  
      if (!isAllowed) {
        console.log(`URL: ${url} -> block`);
      } else {
        console.log(`URL: ${url} -> allow`);
      }
    }
  });
