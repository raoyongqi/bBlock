// 创建并注入HTML元素
const buttonHtml = `
  <div id="downloadBtn" style="
    position: fixed;
    right: 20px;
    top: 50%;
    transform: translateY(-50%);
    padding: 10px 20px;
    background-color: #4CAF50;
    color: white;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    font-size: 16px;
  ">
    Download Blocked URLs
  </div>
`;

// 插入按钮到页面的 body 中
const div = document.createElement('div');
div.innerHTML = buttonHtml;
document.body.appendChild(div);

document.getElementById('downloadBtn').addEventListener('click', function () {
  // 获取存储的被拦截的 URL（从 localStorage 中获取）
  const blockedUrls = JSON.parse(localStorage.getItem('blockedUrls')) || [];

  // 将每个 URL 用引号包裹并创建 JS 数组
  const formattedUrls = blockedUrls.map(url => `"${url}"`).join(',\n');
  const jsContent = `const blockedUrls = [\n${formattedUrls}\n];\nexport default blockedUrls;`;

  // 创建 Blob 对象
  const blob = new Blob([jsContent], { type: 'application/javascript' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'blocked_urls.js'; // 下载为 .js 文件
  link.click();
});
