# ARM固件基址探测工具

该工具是IDA插件，要求IDA 8.0版本以上，将armbasefinder.py放入IDA插件目录。

将固件以基址0装入IDA分析完成后，在反汇编窗口右键即可打开插件，目前支持3种探测方式

![](image-2.png)

![](image-3.png)

# TODO
* 使用C/C++重新实现，Python跑双层循环实在是太慢了，可能是C/C++的百倍以上