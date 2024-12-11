import subprocess
import re
import socket
import threading
import psycopg2
from psycopg2 import sql    
import logging
import signal
import os #se importo os para poder tener una forma de interactuar con el nombre y contraseña que se piden en el codigo


def configurar_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",  # Formato del log
        handlers=[
            logging.FileHandler("/app/logs/eventos.log"),  #ubicacion del archivo donde se guardan los registros
        ]
    )
def obtener_conexionDB():
    try:
        conn = psycopg2.connect(
            host="localhost", 
            database="registro_mensajes",
            user="postgres",
            password="brawlstars"
        )
        print("Se ha establecido conexion con la base de datos {database}")
        logging.info("-obtener_conexionDB: Se ha establecido conexión con la base de datos!")
        return conn
    except Exception as e:
        print(f"Error al conectar con la base de datos: {e}")
        logging.error(f"obtener_conexionDB: NO SE HA PODIDO CONECTAR A LA BASE DE DATOS: {e}")
        return None
    
def registrar_enDB(protocolo, data):
    conex = obtener_conexionDB()
    if not conex:
        return
    try:
        with conex.cursor() as cursor:
            cursor.execute(
                "INSERT INTO mensajes (protocolo, data) VALUES (%s, %s)",
                (protocolo, data)
            )
        conex.commit()
        print(f"Mensaje registrado en la base de datos: {data}, ({protocolo})")
        logging.info(f"Se ha registrado en la base de datos el mensaje: {data}, [{protocolo}]")
    except Exception as e:
        print(f"Error al registrar el mensaje: {e}")
        logging.error("Ha ocurrido un error con el registro en la base de datos")
    finally:
        conex.close()
def crear_punto_de_Acceso( ssid, password): #esta funcion va a ser la encargada de crear el punto de acceso
    try:
        #Al juntar todo el comando para crear el punto de acceso en una lista llamada "instruccion" podemos tener exactitud para no dejar espacios en blanco, etc.
        instruccion = ["nmcli", "dev", "wifi", "hotspot","ifname", "wlan0","ssid", ssid,"password", password]
        
        # Ejecutar el comando a traves de subprocess
        devuelve = subprocess.run(instruccion, text=True, capture_output=True, check=True)
        print(f"-crear_punto_de_Acceso: Punto de acceso creado exitosamente:\n{devuelve.stdout}")
        logging.info(f"Punto de acceso creado exitosamente (SSID): {ssid}")
    except subprocess.CalledProcessError as e:
        print(f"-crear_punto_de_Acceso: Error al crear el punto de acceso:\n{e.stderr}")
        logging.error(f"Ha ocurrido un error al crear el punto de acceso:\n {e.stderr}")
    except Exception as ex:
        print(f"Se produjo un error inesperado: {ex}")
        logging.error(f"-crear_punto_de_Acceso: Se produjo un error inesperado: {ex}")

def Detener_Punto_de_Acceso(id): #y esta funcion detiene el punto de acceso con el comando down
    try:
        # Comando para detener el pto de acceso
        instruccion = ["nmcli", "connection", "down", "id", id]
        # Ejecutar el comando
        devuelve = subprocess.run(instruccion, text=True, capture_output=True, check=True)
        eliminar_punto_de_Acceso(id)
        print(f"Punto de acceso detenido exitosamente:\n{devuelve.stdout}")
        logging.info(f"-Detener_punto_de_Acceso: Se detuvo correctamente el punto de acceso")
    except subprocess.CalledProcessError as e:
        print(f"Error al detener el punto de acceso:\n{e.stderr}")
        logging.error(f"-Detener_punto_de_Acceso: ERROR al detener el punto de acceso:\n{e.stderr}")
    except Exception as ex:
        print(f"Se produjo un error inesperado: {ex}")
        logging.error(f"-Detener_punto_de_Acceso: ERROR inesperado al intentar detener el punto de acceso: {ex}")


def eliminar_punto_de_Acceso(id):
    try:
        instruccion2 =["nmcli", "connection", "delete", "id", id]
        devuelve = subprocess.run(instruccion2, text=True, capture_output=True, check=True)
        print(f"La id para el nuevo punto de acceso se ha reiniciado correctamente:\n{devuelve.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"No hay puntos de acceso previos para eliminar (ignorar advertencia de error):\n{e.stderr}")
    except Exception as ex:
        print(f"Se produjo un error inesperado: {ex}")

def scan_wifi_cercanos():
    try:
        # Ejecutar el comando iwlist scan
        command = ["iwlist", "wlan0", "scan"]
        result = subprocess.run(command, text=True, capture_output=True, check=True)
        output = result.stdout

        # Buscar todos los SSID utilizando expresiones regulares
        ssid_matches = re.findall(r'ESSID:"(.*?)"', output)
        
        # Eliminar duplicados manteniendo el orden
        unique_ssids = list(dict.fromkeys(ssid_matches))

        return unique_ssids

    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar iwlist:\n{e.stderr}")
    except Exception as ex:
        print(f"Se produjo un error inesperado: {ex}")
        return []
    
def tcp_server():
    
    #inicia servidor TCP
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.bind(("0.0.0.0", 12345)) 
    tcp_socket.listen(5)
    print("Servidor TCP en espera de conexiones...")
    logging.info("-tcp_server: Se ha iniciado el servidor TCP")

    while True:
        conn, addr = tcp_socket.accept()
        print(f"Conexión TCP desde {addr}")
        data = conn.recv(1024)
        if validar_paquete(data, "TCP", addr[0]):
            conn.sendall(b"Datos recibidos correctamente (TCP)")
            logging.info("-tcp_server: Se ha recibido un paquete valido por el servidor TCP")
            mensaje = data.decode()
            registrar_enDB("TCP", mensaje)  # Guardar en la base de datos
        else:
            conn.sendall(b"Paquete TCP rechazado por ser invalido.")
            logging.error(f"-tcp_server: OJO Paquete TCP rechazado por ser invalido")

        conn.close()

def validar_paquete(datos, protocolo, ip):

    #Valida los requisitos de los protocolos, si no los cumplen se llama el bloquea_ip
    try:
        # Ver si hay datos vacíos
        if not datos:
            print(f"[{protocolo}] Se ha recibido un paquete vacio.")
            logging.warning("-validar_paquete: ADVERTENCIA Se ha recibifo un paquete vacio")
            return False
        
        # Confirmar longitud
        if len(datos) < 20 and protocolo == "TCP":
            print(f"[{protocolo}] |Advertencia: Paquete TCP invalido, su longitud es menor 20 bytes")
            bloquear_ip_maliciosa(ip)
            logging.warning(f"-validar_paquete: Se ha bloqueado la ip: {ip} por enviar un paquete invalido")
            return False
        
        elif len(datos) < 8 and protocolo == "UDP":
            print(f"[{protocolo}] |Advertencia: Paquete UDP invalido, su longitud es menor a 8 bytes")
            bloquear_ip_maliciosa(ip)
            logging.warning(f"-validar_paquete: Se ha bloqueado la ip: {ip} por enviar un paquete invalido")

            return False
        
        # ASCII seguro
        if not datos.decode(errors="ignore").isascii():
            print(f"[{protocolo}] |Advertencia: Paquete contiene caracteres no ASCII.")
            bloquear_ip_maliciosa(ip)
            logging.warning(f"-validar_paquete: Se ha bloqueado la ip: {ip} por enviar un paquete invalido")

            return False
        
        print(f"[{protocolo}] Exito: Se ha recibido un paquete valido")
        logging.info(f"-validar_paquete: Success se ha recibido un paquete valido")
        return True

    except Exception as ex:
        print(f"[{protocolo}] Error al validar el paquete: {ex}")
        logging.error(f"-validar_paquete: ERROR inesperado al validar paquete: {ex}")
        return False

def udp_server():

    #inicio servidor UDP
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("0.0.0.0", 12346))  
    print("Servidor UDP en espera de mensajes...")
    logging.info("-udp_server: Se ha iniciado el servidor UDP")

    while True:
        data, addr = udp_socket.recvfrom(1024)
        if validar_paquete(data, "UDP",addr[0]):
            udp_socket.sendto(b"Datos recibidos correctamente (UDP)", addr)
            logging.info("-udp_server: Se ha recibido un paquete valido por el servidor UDP")
            mensaje = data.decode()
            registrar_enDB("UDP", mensaje)  # Guardar en la base de datos

        else:
            udp_socket.sendto(b"Paquete UDP rechazado por ser invalido.", addr)
            logging.error(f"-udp_server: OJO Paquete UDP rechazado por ser invalido")
        
def bloquear_ip_maliciosa(ip): #se bloquean las ip a traves de reglas con iptables
    try:
        instruccion = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        subprocess.run(instruccion, check=True)
        print(f"Dispositivo con ip: {ip} ha sido bloqueado por enviar datos invalidos.")
        logging.info(f"BLOQUEADOR: se ha blqueado la ip {ip} con exito")
    except subprocess.CalledProcessError as e:
        print(f"Error al bloquear ip: {ip}: {e.stderr}")
        logging.error(f"Error al bloquear ip: {ip}: {e.stderr}")
    except Exception as ex:
        print(f"Se produjo un error inesperado al bloquear ip: {ip}: {ex}")

def iniciar_tshark(): #para integrar wireshark se uso tshark por código
    
    comando_tshark = ["tshark", "-i", "wlan0", "-f", "tcp or udp", "-w", "/app/logs/captura_trafico.pcap"]
    try:
        proceso = subprocess.Popen(comando_tshark, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print("Tshark está capturando el tráfico de red...")
        logging.info("Tshark iniciado para capturar tráfico de red. \n Para ver el trafico de red hay que acceder a /app/logs/captura_trafico" )
        return proceso
    except Exception as e:
        print(f"Error al iniciar tshark: {e}")
        logging.error(f"Error al iniciar tshark: {e}")
        return None


if __name__ == "__main__": #en el main se piden el nombre y contraseña de la red a crear (se pueden cambiar en el docker-compose.yml)
    configurar_logging()
    logging.info("Comenzando escaneo de redes cercanas...")
    print("Comenzando escaneo de redes cercanas...")
    lista_redes = scan_wifi_cercanos()
    print(f"Resultados: {lista_redes}")
    logging.info(f"Redes Encontradas: {lista_redes}")
    while True:
        print("Ingrese el nombre de la red que se creará como punto de acceso (ssid): ")
        Nombre_wifi = os.getenv("SSID", "Wifi_default")
        logging.info(f"EL nombre ingresado por codigo es: {Nombre_wifi}")
        print("Ingrese la contraseña del punto de acceso (Largo minimo 8 caracteres): ")
        Contraseña_wifi = os.getenv("CONTRASENA","contra_default")
        logging.info(f"La contrasena ingresada es valida: {Contraseña_wifi}")
        if Nombre_wifi in lista_redes:
            print("Error: El nombre ya existe, intente con otro.")
            logging.exception("El nombre de red ingresado ya existe")
        elif len(Contraseña_wifi) < 8:
            print("Error: La contraseña debe tener al menos 8 caracteres.")
            logging.exception("La contraseña ingresada no cumple con el largo minimo")
        else:
            break

    logging.info("crear_punto_de_Acceso: Se esta creando el punto de acceso...")
    print("Se está creando el punto de acceso ...")
    crear_punto_de_Acceso(Nombre_wifi, Contraseña_wifi)
    proceso_tshark = iniciar_tshark() #inicio de servicios
    tcp_thread = threading.Thread(target=tcp_server, daemon=True)
    udp_thread = threading.Thread(target=udp_server, daemon=True)

    tcp_thread.start()
    udp_thread.start()

    print("Servidores TCP y UDP están en ejecución...")
    try:
        tcp_thread.join()
        udp_thread.join()

    except KeyboardInterrupt:
        print("Servidores detenidos.")
        #originalmente se detenian algunos servicios por medio de ctl+c pero eso ahora detiene el docker por lo que
        #no están añadidos en el main (como detener_punto_acceso)
            


