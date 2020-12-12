# QHash
## 简介
计算文件各种 hash。  


## 使用方法
3种使用方法：
1. 选中文件右键点击"calc hash with QHash"（推荐）
2. 将文件拖到qhash.exe
3. 命令行执行命令：`qhash.exe <file_path>`


## 编译相关

pyinstaller打包命令：  
```
pyinstaller --icon qhash.ico --onefile qhash.py
```
可执行文件可以在dist文件夹找到  

可以用 NSIS 编译 qhash.nsi 来制作安装包  