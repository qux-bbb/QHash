# QHash
## 简介
计算文件各种 hash，默认计算md5、sha1。  


## 使用方法
3种使用方法：
1. 选中文件右键点击"calc hash with QHash"（推荐）
2. 将文件拖到qhash.exe
3. 命令行执行命令，命令行可选择计算各种hash


## 编译相关

pyinstaller打包命令：  
```
pyinstaller --icon qhash.ico --onefile qhash.py
```
可执行文件可以在dist文件夹找到  
如果要在win7下使用qhash，需要使用python3.7的pyinstaller打包，避免出现win7运行缺少dll的情况  

可以用 NSIS 编译 qhash.nsi 来制作安装包  
