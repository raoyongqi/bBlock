// Define blocked and allowed URL patterns
const blockedUrls = [
    "*://www.google.com/search*",
    "*://*firefox*",
    "*://camo.githubusercontent.com/*"
  ];
  
  const allowedUrls = [
    "https://reproducible-builds.org/*",
    "https://chatgpt.com/*",
    "https://github.com/*"
  ];
  
  // Generate unique rule IDs
  const blockedRules = blockedUrls.map((url, index) => ({
    id: index + 1, // Unique ID for each rule
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: url,
      resourceTypes: ["main_frame"]
    }
  }));
  
  const allowedRules = allowedUrls.map((url, index) => ({
    id: blockedUrls.length + index + 1, // Unique ID for allowed rules
    priority: 1,
    action: { type: "allow" },
    condition: {
      urlFilter: url,
      resourceTypes: ["main_frame"]
    }
  }));
  
  // Update dynamic rules
  chrome.runtime.onInstalled.addListener(() => {
    // Get all existing rules
    chrome.declarativeNetRequest.getDynamicRules((existingRules) => {
      // Print existing rules to the console
      console.log("Existing rules:", existingRules);
  
      // Extract existing rule IDs
      const existingRuleIds = existingRules.map((rule) => rule.id);
  
      // Remove existing rules to avoid ID conflicts
      chrome.declarativeNetRequest.updateDynamicRules(
        {
          removeRuleIds: existingRuleIds, // Remove all existing rules
          addRules: [...blockedRules, ...allowedRules] // Add new rules
        },
        () => {
          if (chrome.runtime.lastError) {
            console.error("Failed to update rules:", chrome.runtime.lastError.message);
          } else {
            console.log("Rules updated successfully.");
          }
        }
      );
    });
  });
  