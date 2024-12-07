let clickCount = 0; // 初始化点击次数
const maxClicks = 10; // 最大点击次数

const intervalId = setInterval(() => {
  // 获取按钮元素
  const button = document.querySelector('#j-refresh-btn');
  
  // 如果按钮存在，则点击
  if (button) {
    button.click();
    clickCount++;
    console.log(`Clicked ${clickCount} times`);
  } else {
    console.log('Button not found');
    clearInterval(intervalId); // 如果按钮不存在，停止计时器
  }

  // 如果已经点击 10 次，停止计时器
  if (clickCount >= maxClicks) {
    clearInterval(intervalId);
    console.log('Reached maximum click count');
  }
}, 1000); // 每秒钟执行一次
