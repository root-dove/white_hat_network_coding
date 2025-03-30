실행을 하려면 pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf); 여기에 "ens33"을 자신의 어뎁터로 변경을 하고
sudo gcc -o network_capture network_capture.c -lpcap 
한 뒤
sudo ./network_capture 하면 됩니다
