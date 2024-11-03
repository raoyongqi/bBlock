this._setupMyNewAddon();


async _setupMyNewAddon() {
    // This add-on shouldn't be disabled either.
    const ID = "addons-my-new-addon@mozilla.com";

    // 尝试获取已有的扩展
    let addon = await lazy.AddonManager.getAddonByID(ID);

    // 尝试首次安装扩展，并在 Firefox 更新时安装
    addon =
      (await lazy.AddonManager.maybeInstallBuiltinAddon(
        ID,
        "1.0", // 指定插件版本
        "resource://builtin-addons/block/" // 插件资源路径
      )) || addon;

    // 如果插件未激活，则启用它
    if (!addon.isActive) {
      addon.enable();
    }
},
