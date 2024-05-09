# syslog-echo-server
Syslog echo server for k8s. 

ARM image litded/syslog_server

Собирает логи на 514 UDP порту и выводит в консоль. Чтобы это имело смысл, в кластере должен быть установлен сборщик логов.