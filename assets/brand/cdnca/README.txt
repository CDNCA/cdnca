cdnca 默认品牌资源（fix-brandkit，方案 A：圆角方块里的 "c" + 节点点）。
SVG 为源，scripts/brand/export.sh 生成全部 PNG/ICO/JPEG 并拷到各前端 public/。
颜色：主色 #2563eb（--cdnca-color-primary），渐变 #3b82f6 → #1d4ed8，字标浅底 #1e3a8a、深底 #ffffff。
字标是几何路径（不依赖字体），导出在任何机器上一致。
concepts/ 是 A/B/C 三个候选方案与对比页，仅留档。
login-ad-en.text / login-ad-zh-TW.text 是英文/繁体广告的文字层：export.sh 去掉 login-ad.svg 的 <text> 行后换入，导出 ad-en.jpeg / ad-zh-TW.jpeg（主控按界面语言选内置图，自定义上传不受影响）。
