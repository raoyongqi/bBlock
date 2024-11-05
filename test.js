// 正则表达式定义：匹配包含 "firefox" 的 URL
const regexFilter = /.*firefox.*/i;

// 要测试的 URL 列表
const urls = [
    "https://www.mozilla.org/en-US/firefox/new/",
    "https://firefox.com",
    "https://example.com/some-firefox-page",
    "https://example.com/about"
];

// 遍历 URL 并检查是否被“屏蔽”
urls.forEach(url => {
    if (regexFilter.test(url)) {
        console.log(`URL: ${url} -> block`);
    } else {
        console.log(`URL: ${url} -> allow`);
    }
});
