Registro avances del código de redes
OJO para la correcta ejecución del código solo se necesita que el host tenga NetworkManager y postgres en su sistema. 
No pudimos utilizar hostapd junto a dnmasq debido a que no se podía conectar a la redes que se creaban con ellos, es por eso que se tuvo que optar por nmcli (Networkmanager) para poder crear el punto de acceso remoto en la raspberry.
Se puede encontrar más información en lso archivos del código principal CrearHotspot.py y los docker files.
