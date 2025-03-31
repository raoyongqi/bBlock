
const beginWithStar = [
  "*.icbc.com.cn",
"*.qt.io",
"*.ku.edu",
"*.psu.edu",
"*.nih.gov",
"*.pymc.io",
"*.126.net",
"*.epfl.ch",
"*.acm.org",
"*.unl.edu",
"*.rsc.org",
"*.doi.org",
"*.iop.org",
"*.upc.edu",
"*.itch.io",
"*.kde.org",
"*.10086.cn",
"*.cnzz.com",
"*.esri.com",
"*.ieee.org",
"*.25pp.com",
"*.9game.cn",
"*.nasa.gov",
"*.amap.com",
"*.deno.com",
"*.gyan.dev",
"*.deno.dev",
"*.live.com",
"*.usgs.gov",
"*.ufrpe.br",
"*.siam.org",
"*.yale.edu",
"*.posit.co",
"*.ssrn.com",
"*.kaggle.io",
"*.mlr.press",
"*.wiley.com",
"*.r-lib.org",
"*.google.de",
"*.netzel.pl",
"*.sun.ac.za",
"*.azure.com",
"*.osgeo.org",
"*.github.io",
"*.theoj.org",
"*.npmjs.com",
"*.arxiv.org",
"*.cgiar.org",
"*.cdn-go.cn",
"*.clarity.ms",
"*.kaggle.com",
"*.google.com",
"*.office.net",
"*.privado.ai",
"*.yeepay.com",
"*.nature.com",
"*.52pojie.cn",
"*.sinaimg.cn",
"*.wpscdn.com",
"*.mmstat.com",
"*.omtrdc.net",
"*.jquery.com",
"*.nvidia.com",
"*.openai.com",
"*.qqmail.com",
"*.github.com",
"*.office.com",
"*.aliapp.org",
"*.alipay.com",
"*.oracle.com",
"*.aliyun.com",
"*.lzu.edu.cn",
"*.gradle.org",
"*.xarray.dev",
"*.dkut.ac.ke",
"*.alicdn.com",
"*.chatgpt.com",
"*.sciendo.com",
"*.hsforms.net",
"*.mail.qq.com",
"*.addthis.com",
"*.neea.edu.cn",
"*.holoviz.org",
"*.typekit.net",
"*.gstatic.com",
"*.informs.org",
"*.els-cdn.com",
"*.hubspot.com",
"*.sagepub.com",
"*.hanspub.org",
"*.clemson.edu",
"*.apta.gov.cn",
"*.mlr-org.com",
"*.algolia.net ",
"*.graph.qq.com",
"*.adobedtm.com",
"*.newrelic.com",
"*.figshare.com",
"*.aligames.com",
"*.elsevier.com",
"*.springer.com",
"*.berkeley.edu",
"*.mdpi-res.com",
"*.aliyuncs.com",
"*.torontomu.ca",
"*.aegis.qq.com",
"*.uclouvain.be",
"*.jsdelivr.net",
"*.riskified.com",
"*.azureedge.net",
"*.music.126.net",
"*.oaistatic.com",
"*.amazonaws.com",
"*.rust-lang.org",
"*.ucdl.pp.uc.cn",
"*.clarivate.com",
"*.codabench.org",
"*.weixin.qq.com",
"*.microsoft.com",
"*.wandoujia.com",
"*.cookielaw.org",
"*.cambridge.org",
"*.r-project.org",
"*.strongvpn.com",
"*.scraperapi.com",
"*.googleapis.com",
"*.tidymodels.org",
"*.readthedocs.io",
"*.biologists.com",
"*.conicet.gov.ar",
"*.strongtech.org",
"*.tensorflow.org",
"*.cloudflare.com",
"*.iopscience.com",
"*.captcha.qq.com",
"*.cloudfront.net",
"*.pressbooks.pub",
"*.sams-sigma.com",
"*.allenpress.com",
"*.jinshujucdn.com",
"*.silverchair.com",
"*.qutebrowser.org",
"*.ptlogin2.qq.com",
"*.commoncrawl.org",
"*.readthedocs.org",
"*.googlesource.com",
"*.gongkaoshequ.com",
"*.s3.amazonaws.com",
"*.audacityteam.org",
"*.jinshujufiles.com",
"*.biomedcentral.com",
"*.sciencedirect.com",
"*.alipayobjects.com",
"*.scienceconnect.io",
"*.dropboxstatic.com",
"*.springernature.io",
"*.ansfoundation.org",
"*.oaiusercontent.com",
"*.springernature.com",
"*.alibabachengdun.com",
"*.microsoftonline.com",
"*.researchcommons.org",
"*.msftconnecttest.com",
"*.google-analytics.com",
"*.googletagmanager.com",
"*.taylorandfrancis.com",
"*.githubusercontent.com",
"*.kaggleusercontent.com",
"*.journal-grail.science",
"*.googlesyndication.com",
"*.immersivetranslate.com",
"*.cloudflareinsights.com",
"*.simpleanalyticscdn.com",
"*.storage.googleapis.com",
"*.sonaliyadav.workers.dev",
"*.sciencedirectassets.com",
"*.webofscience.clarivate.cn",
"*.visualwebsiteoptimizer.com",
"*.search.serialssolutions.com"
];
const beginWithoutStar = [
  "t.me",
  "t.co",
  "t.co"
]
const allowedUrls = beginWithStar.concat(beginWithoutStar);  // concat 方法 gpt认为效率更高
            
const blockedUrls = [
  "*://www.google.com/search*",
  ".*firefox.*",
  ".*firefox",
  "*://camo.githubusercontent.com/*"
];

const onBeforeRequest = (details) => {
  const url = new URL(details.url);
  const host = url.hostname;

  const isBlocked = blockedUrls.some(pattern => {
    const regex = new RegExp(pattern.replace(/\*/g, '.*'));
    return regex.test(details.url);
  });

  if (isBlocked) {
    console.log(`Blocked URL: ${details.url}`);

    let blockedList = JSON.parse(localStorage.getItem("blockedUrls")) || [];

    blockedList.push(details.url);

    localStorage.setItem("blockedUrls", JSON.stringify(blockedList));

    return { cancel: true };
  }

  const isAllowed = allowedUrls.some(pattern => {


    if (pattern.startsWith("*.") && host.endsWith(pattern.slice(2))) {
      return true;
    }
    return host === pattern || host === 'www.' + pattern;
  });

  if (!isAllowed) {
    console.log(`Blocked URL: ${details.url}`);

    let blockedList = JSON.parse(localStorage.getItem("blockedUrls")) || [];

    blockedList.push(details.url);

    localStorage.setItem("blockedUrls", JSON.stringify(blockedList));

    return { cancel: true };
  }

  return { cancel: false };
};

browser.webRequest.onBeforeRequest.addListener(
  onBeforeRequest,
  { urls: ["<all_urls>"] },
  ["blocking"]
);
browser.browserAction.onClicked.addListener(() => {
  const blockedUrls = JSON.parse(localStorage.getItem('blockedUrls')) || [];

  if (blockedUrls.length === 0) {
    alert("No URLs to download.");
    return;
  }

  const formattedUrls = blockedUrls.map(url => `"${url}"`).join(',\n');
  const jsContent = `const blockedUrls = [\n${formattedUrls}\n];\nexport default blockedUrls;`;

  const blob = new Blob([jsContent], { type: 'application/javascript' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'blocked_urls.js';
  link.click();
});
