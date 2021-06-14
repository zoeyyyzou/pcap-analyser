# Pcap-analyser

> This repository concerns only on extracting features from pcap files.   
>
> The code which is used to pull feed and save them into database is in another repository.  
> 
> Please checkout support-email-extractor brunch which can be used to test. The master brunch is used for front-end and isn't completed.  


## Getting Started 使用指南
### Prerequisites
```
python 3.8.6
```

### Installation 安装
Windows:
```sh
pip install -r requirements.txt
```
### Run 
```sh
git checout support-email-test_flow_extractor
python test_flow_extractor.py <pcap file name>
 
```

### Usage example 使用示例
Test pcap files are:  ids1.pcap ftp.pcap ftp2.pcap ftp3.pcap imap.pcap smtp1.pcap pop3.pcap   
Ids1.pcap file is a public dataset.
```sh
python test_flow_extractor.py ids1.pcap
python test_flow_extractor.py ftp.pcap
```

## Authors 作者

* **Yangyi Zou**

