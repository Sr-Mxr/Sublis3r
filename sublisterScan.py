import os
import sys
import json
import requests
import argparse
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime

class Sublist3rScan:
    def __init__(self):
        self.api_key = None
        self.config_file = "sublist3r_config.json"
        self.load_config()
        
        # Servicios básicos (gratuitos)
        self.basic_services = [
            'https://api.securitytrails.com/v1/domain/{domain}/subdomains',
            'https://certspotter.api.mozillait.org/v1/issuances?domain={domain}',
            'https://crt.sh/?q=%25.{domain}&output=json'
        ]
        
        # Servicios avanzados (requieren API)
        self.advanced_services = [
            'https://api.threatminer.org/v2/domain.php?q={domain}&rt=5',
            'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns'
        ]

    def mostrar_banner(self):
        print("""
        ╔══════════════════════════════════╗
        ║                                  ║
        ║      Sublist3r-Scan v1.0         ║
        ║                       by:Mxr     ║
        ║  Herramienta de enumeración      ║
        ║    de subdominios avanzada       ║
        ╚══════════════════════════════════╝
        """)

    def load_config(self):
        """Carga la configuración desde archivo"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.api_key = config.get('api_key', None)
        except Exception as e:
            print(f"Error al cargar configuración: {e}")

    def save_config(self):
        """Guarda la configuración en archivo"""
        try:
            config = {'api_key': self.api_key}
            with open(self.config_file, 'w') as f:
                json.dump(config, f)
        except Exception as e:
            print(f"Error al guardar configuración: {e}")

    def configurar_api(self):
        """Configura la API key"""
        self.api_key = input("\nIngrese su API key: ")
        self.save_config()
        print("API key guardada exitosamente!")

    def mostrar_menu(self):
        while True:
            os.system('clear')
            self.mostrar_banner()
            
            print("\n=== Opciones de Búsqueda ===")
            print("1. Búsqueda Rápida (Servicios básicos)")
            print("2. Búsqueda Avanzada (Todos los servicios)")
            print("3. Búsqueda Personalizada")
            print("4. Configuración")
            print("5. Salir")
            
            opcion = input("\nSeleccione una opción: ")
            
            if opcion == "1":
                self.busqueda_rapida()
            elif opcion == "2":
                self.busqueda_avanzada()
            elif opcion == "3":
                self.busqueda_personalizada()
            elif opcion == "4":
                self.menu_configuracion()
            elif opcion == "5":
                print("\n¡Gracias por usar Sublist3r-Scan!")
                sys.exit(0)

    def busqueda_rapida(self):
        """Realiza una búsqueda rápida usando solo servicios básicos"""
        domain = input("\nIngrese el dominio a escanear: ")
        self.ejecutar_busqueda(domain, self.basic_services)
        input("\nPulse Enter para continuar...")

    def busqueda_avanzada(self):
        """Realiza una búsqueda avanzada usando todos los servicios"""
        if not self.api_key:
            print("\n¡Error! Necesita configurar una API key para esta opción.")
            time.sleep(2)
            return
        
        domain = input("\nIngrese el dominio a escanear: ")
        services = self.basic_services + self.advanced_services
        self.ejecutar_busqueda(domain, services)
        input("\nPulse Enter para continuar...")

    def busqueda_personalizada(self):
        """Permite seleccionar servicios específicos"""
        domain = input("\nIngrese el dominio a escanear: ")
        
        print("\nServicios disponibles:")
        for i, service in enumerate(self.basic_services + self.advanced_services, 1):
            print(f"{i}. {service.split('/')[-2]}")
        
        servicios_seleccionados = []
        while True:
            try:
                selecciones = input("\nIngrese los números de los servicios (separe por comas): ").split(',')
                for sel in selecciones:
                    idx = int(sel.strip()) - 1
                    if 0 <= idx < len(self.basic_services + self.advanced_services):
                        servicios_seleccionados.append(self.basic_services[idx] if idx < len(self.basic_services) else self.advanced_services[idx-len(self.basic_services)])
                    else:
                        print("Número inválido ignorado")
                break
            except ValueError:
                print("Por favor ingrese números válidos separados por comas")
        
        self.ejecutar_busqueda(domain, servicios_seleccionados)
        input("\nPulse Enter para continuar...")

    def menu_configuracion(self):
        """Muestra el menú de configuración"""
        while True:
            os.system('clear')
            self.mostrar_banner()
            
            print("\n=== Configuración ===")
            print("1. Cambiar API Key")
            print("2. Ver estadísticas")
            print("3. Volver al menú principal")
            
            opcion = input("\nSeleccione una opción: ")
            
            if opcion == "1":
                self.configurar_api()
            elif opcion == "2":
                self.ver_estadisticas()
            elif opcion == "3":
                break
            
            input("\nPulse Enter para continuar...")

    def ejecutar_busqueda(self, domain, services):
        """Ejecuta la búsqueda de subdominios"""
        subdomains = []
        
        print(f"\nIniciando búsqueda en {domain}...")
        print(f"Utilizando {len(services)} servicios")
        
        with ThreadPoolExecutor(max_workers=len(services)) as executor:
            futures = []
            for service in services:
                futures.append(executor.submit(self._fetch_subdomains, service.format(domain=domain)))
            
            for future in as_completed(futures):
                try:
                    new_domains = future.result()
                    subdomains.extend(new_domains)
                except Exception as e:
                    print(f"Error en búsqueda: {e}")
        
        unique_subdomains = sorted(set(subdomains))
        print(f"\nSe encontraron {len(unique_subdomains)} subdominios únicos")
        if len(unique_subdomains) == 0:
            print("\nNo se encontraron subdominios. No se realizará guardado.")
            return
            
        guardar = input("\n¿Desea guardar los resultados? (s/n): ")
        if guardar.lower() == 's':
            filename = f"subdomains_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                for domain in unique_subdomains:
                    f.write(f"{domain}\n")
            print(f"\nResultados guardados en {filename}")

    def _fetch_subdomains(self, url):
        """Realiza la petición HTTP y extrae los subdominios"""
        try:
            headers = {}
            if 'securitytrails' in url and self.api_key:
                headers['APIKEY'] = self.api_key
            
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                return self._parse_response(url, response.text)
        except Exception as e:
            print(f"Error al consultar {url}: {e}")
        return []

    def _parse_response(self, url, content):
        """Parsea la respuesta según el servicio utilizado"""
        domains = []
        try:
            if 'securitytrails' in url:
                data = json.loads(content)
                domains = [item for item in data['subdomains']]
            elif 'certspotter' in url:
                data = json.loads(content)
                for cert in data:
                    for dns_names in cert['dns_names']:
                        domains.append(dns_names)
            elif 'crt.sh' in url:
                data = json.loads(content)
                for item in data:
                    domains.append(item['common_name'])
            elif 'threatminer' in url:
                data = json.loads(content)
                domains = [item['domain'] for item in data['subdomains']]
            elif 'alienvault' in url:
                data = json.loads(content)
                domains = [item['indicator'] for item in data['passive_dns']]
        except json.JSONDecodeError:
            pass
        return domains

    def ver_estadisticas(self):
        """Muestra estadísticas de uso"""
        print("\n=== Estadísticas ===")
        print(f"API Key configurada: {'Sí' if self.api_key else 'No'}")
        print(f"Última ejecución: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def main():
    scanner = Sublist3rScan()
    scanner.mostrar_menu()

if __name__ == '__main__':
    main()
