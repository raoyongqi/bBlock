const allowedUrls = [
  "reproducible-builds.org",
  "chatgpt.com",
  "github.com",
  "code.earthengine.google.com",
  "drive.google.com",
  "google.com",
  "*.google.com",
  "arcgis.com",
  "github.githubassets.com",
  "*.esri.com",
  "strongvpn.com",
  "*.strongvpn.com",
  "kimi.com",
  "*.oaiusercontent.com",
  "*.amap.com",
  "yuque.com",
  "alipay.com",
  "*.microsoftonline.com",
  "accounts.google.com.np",
  "browser-intake-datadoghq.com",
  "featureassets.org",
  "prodregistryv2.org",
  "alipayobjects.com",
  "*.alipayobjects.com",
  "doi.org",
  "*.office.com",
  "*.codabench.org",
  "*.elsevier.com",
  "elsevier.com",
  "mdpi.com",
  "ngcc.cn",
  "nwr.gov.cn",
  "developer.android.com",
  "tianditu.gov.cn",
 "doi.org",
  "gee-community-catalog.org",
  "wiley.com",
  "*.wiley.com",
  "osgeo.org",
  "*.osgeo.org",
  "pypi.org",
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
  "*.graph.qq.com",
  "*.wpscdn.com",
  "redux-toolkit.js.org",
  "react-redux.js.org",
  "imgcache.qq.com",
  "webextension.org",
  "*.ptlogin2.qq.com",
  "*.captcha.qq.com",
  "res.wx.qq.com",
  "aegis.qq.com",
  "*.cdn-go.cn",
   "*.aegis.qq.com",
  "captcha.gtimg.com",
  "flickerfree.org",
  "passmark.com",
  "python.org",
  "*.microsoft.com",
  "rustup.rs",
  "*.githubusercontent.com",
  "*.qqmail.com",
  "*.oaistatic.com",
  "fonts.gstatic.com",
  "*.gstatic.com",
  "*.googleapis.com",
  "*.cloudflare.com",
  "*.nasa.gov",
  "git-scm.com",
  "localhost", // 添加 localhost
  "127.0.0.1", // 添加 127.0.0.1,
  "wps.com",
  "meeting.qq.com",
  "*.aliyun.com",
  "*.alicdn.com",
  "*.github.io",
  "apktool.org",
  "*.usgs.gov",
  "researchgate.net",
  "sciencedirect.com",
  "msftconnecttest.com",
  "redux.js.org",
  "wandoujia.com",
    "10.10.0.166",
    "*.alipay.com",
    "lgincdnvzeuno.azureedge.net",
    "accounts.google.de",
    "zenodo.org",
    "ojs.aaai.org",
    "*.office.net",
    "*.readthedocs.io",
    "*.github.com",
  "*.aliyuncs.com",
      "*.wandoujia.com",
      "zz.bdstatic.com",
      ",*.cnzz.com",
      "*.alibabachengdun.com",
      "*.sinaimg.cn",
    " fourier.taobao.com",
    "*.9game.cn",
    "*.mmstat.com",
    "*.ucdl.pp.uc.cn",
    "*.25pp.com",
    "hm.baidu.com",
    "detectportal.firefox.com",
    "*.lzu.edu.cn",
    "*.s3.amazonaws.com",
    "s.gravatar.com",
    "jsj.top",
    "*.jinshujufiles.com",
    "nodejs.org",
    "music.163.com",
    "*.jinshujucdn.com",
    "*.newrelic.com",
    "*.music.126.net",
    "sp0.baidu.com",
    "*.126.net",
    "*.163.com",
    "*.aliapp.org",
    "*.aligames.com",
    "qzapp.qlogo.cn",
    "docs-neteasecloudmusicapi.vercel.app" ,
    "googletagmanager.com",
    "*.googletagmanager.com",
    "unpkg.com",
    "*.googlesyndication.com",
    "gitlab.com",
    "*.npmjs.com",
    "lib.baomitu.com",
    "fonts.loli.net",
   "www.npmjs.com",
   "electronjs.org",
   "gdal.org",
   "numfocus.org",
   "studiostaticassetsprod.azureedge.net",
   "vite.dev",
   "report.qqweb.qq.com",
   "ssl.ptlogin2.graph.qq.com",
   "ant.design",
   "tauri.app",
   "docs.geetest.com",
   "www.52pojie.cn",
   "*.52pojie.cn",
   "frida.re",
    "www.wjx.cn",
]; 
const blockedUrls = [
  "*://www.google.com/search*",
  ".*firefox.*",
  ".*firefox" // 用于阻止包含“firefox”的 URL 的正则表达式
];

const onBeforeRequest = (details) => {
  const url = new URL(details.url);
  const host = url.hostname;

  // 检查是否在被阻止的 URL 列表中
  const isBlocked = blockedUrls.some(pattern => {
    const regex = new RegExp(pattern.replace(/\*/g, '.*'));
    return regex.test(details.url); // 检查整个 URL
  });

  if (isBlocked) {
    console.log(`Blocked URL: ${details.url}`);
    return { cancel: true }; // 拦截请求
  }

  // 检查是否在允许的 URL 列表中
  const isAllowed = allowedUrls.some(pattern => {
    // 处理通配符
    if (pattern.startsWith("*.") && host.endsWith(pattern.slice(2))) {
      return true;
    }
    return host === pattern || host === 'www.' + pattern; // 检查主机名
  });

  if (!isAllowed) {
    console.log(`Blocked URL: ${details.url}`);
    return { cancel: true }; // 拦截请求
  }

  return { cancel: false }; // 允许请求
};

// 监听所有请求
browser.webRequest.onBeforeRequest.addListener(
  onBeforeRequest,
  { urls: ["<all_urls>"] },
  ["blocking"]
);
