import json
import pandas as pd
import glob
import os 
from lxml import etree # <--- Importante para los pasos 3.1 y 3.2

# ----------------------------------------------------
#               PASO 2: PROCESAR CVE (Tu código)
# ----------------------------------------------------
cve_path = r'C:\Users\Eloi\Desktop\UDC\IA\Q7\TAPLN\dataset' 
search_pattern = os.path.join(cve_path, 'nvdcve-2.0-*.json')

print(f"Buscando archivos en: {cve_path}")
print(f"Usando el patrón de búsqueda: {search_pattern}")

json_files = glob.glob(search_pattern)

print(f"Archivos JSON 2.0 encontrados: {len(json_files)}")

if not json_files:
    print("\n¡ERROR! No se encontraron archivos. Verifica que la ruta cve_path es correcta.")
    print("El script se detendrá.")
    exit() 

cve_list = []

for file in json_files:
    print(f"Procesando archivo: {os.path.basename(file)}") 
    with open(file, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
        for item in data.get('vulnerabilities', []):
            cve_data = item.get('cve', {})
            cve_id = cve_data.get('id', 'N/A')
            
            description = 'N/A'
            if cve_data.get('descriptions'):
                for desc in cve_data['descriptions']:
                    if desc['lang'] == 'en':
                        description = desc['value']
                        break
            
            base_score = 'N/A' # Valor por defecto
            metrics = cve_data.get('metrics', {}) # Obtenemos el objeto 'metrics'

            # 1. Intentamos buscar v4.0
            if metrics.get('cvssMetricV40'):
                base_score = metrics['cvssMetricV40'][0]['cvssData']['baseScore']
            
            # 2. Si no, intentamos v3.1
            elif metrics.get('cvssMetricV31'):
                base_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
            
            # 3. Si no, intentamos v3.0
            elif metrics.get('cvssMetricV30'):
                base_score = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
            
            # 4. Si no, intentamos v2.0 (muy común en CVEs antiguos)
            elif metrics.get('cvssMetricV2'):
                base_score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
            
            cwe_id = 'N/A'
            if cve_data.get('weaknesses'):
                if cve_data['weaknesses'][0].get('description'):
                    for desc_cwe in cve_data['weaknesses'][0]['description']:
                        if desc_cwe['lang'] == 'en':
                            cwe_id = desc_cwe['value']
                            break

            cve_list.append({
                'cve_id': cve_id,
                'description': description,
                'cvss_score': base_score,
                'cwe_id': cwe_id
            })

cve_df = pd.DataFrame(cve_list)
cve_df = cve_df[cve_df['cwe_id'] != 'N/A'] 
print("\nDatos de CVE procesados:")
print(f"Total de CVEs con CWE asociado: {len(cve_df)}")
print(cve_df.head())

# ----------------------------------------------------
#            PASO 3.1: PROCESAR CWE
# ----------------------------------------------------

# --- ¡ACTUALIZA ESTA RUTA! ---
cwe_file = r'C:\Users\Eloi\Desktop\UDC\IA\Q7\TAPLN\dataset\cwec_v4.18.xml' # Ejemplo: r'C:\Users\Eloi\Desktop\dataset\cwec_v4.14.xml'
# ---------------------------

print(f"\nProcesando archivo CWE: {cwe_file}")

tree = etree.parse(cwe_file)
root = tree.getroot()
ns = {'cwe': 'http://cwe.mitre.org/cwe-7'}

cwe_list_xml = []
cwe_capec_map = []

for weakness in root.findall('.//cwe:Weakness', namespaces=ns):
    cwe_id = f"CWE-{weakness.get('ID')}"
    name = weakness.get('Name')
    
    description_element = weakness.find('cwe:Description', namespaces=ns)
    description = description_element.text if description_element is not None else "No description"
    
    cwe_list_xml.append({'cwe_id': cwe_id, 'cwe_name': name, 'cwe_description': description})
    
    for pattern in weakness.findall('.//cwe:Related_Attack_Pattern', namespaces=ns):
        capec_id = f"CAPEC-{pattern.get('CAPEC_ID')}"
        if capec_id != "CAPEC-None":
             cwe_capec_map.append({'cwe_id': cwe_id, 'capec_id': capec_id})

cwe_df = pd.DataFrame(cwe_list_xml)
cwe_capec_df = pd.DataFrame(cwe_capec_map)

print(f"Datos de CWE procesados: {len(cwe_df)} entradas.")
print(f"Mapeo CWE-CAPEC procesado: {len(cwe_capec_df)} relaciones.")
print("--- Muestra de CWEs ---")
print(cwe_df.head())
print("\n--- Muestra de Mapeo CWE-CAPEC ---")
print(cwe_capec_df.head())


# ----------------------------------------------------
#            PASO 3.2: PROCESAR CAPEC
# ----------------------------------------------------

capec_file = r'C:\Users\Eloi\Desktop\UDC\IA\Q7\TAPLN\dataset\capec_v3.9.xml'

print(f"\nProcesando archivo CAPEC: {capec_file}")

tree = etree.parse(capec_file)
root = tree.getroot()

# Este namespace es correcto para CAPEC v3.9
ns = {'capec': 'http://capec.mitre.org/capec-3'}

capec_list = []

for attack in root.findall('.//capec:Attack_Pattern', namespaces=ns):
    capec_id = f"CAPEC-{attack.get('ID')}"
    name = attack.get('Name')
    
    # --- ¡¡AQUÍ ESTÁ LA CORRECCIÓN!! ---
    # En lugar de buscar 'capec:Description/capec:Summary',
    # buscamos 'capec:Description' y extraemos todo su texto.
    
    description_element = attack.find('capec:Description', namespaces=ns) # <--- CAMBIO
    
    description = "No description" # Valor por defecto
    if description_element is not None:
        # Usamos itertext() para obtener todo el texto, igual que hicimos con CWE
        description_text = ''.join(description_element.itertext()).strip()
        if description_text:
            # Limpiamos saltos de línea y espacios múltiples
            description = ' '.join(description_text.split())

    capec_list.append({'capec_id': capec_id, 'capec_name': name, 'capec_description': description})

capec_df = pd.DataFrame(capec_list)
print(f"Datos de CAPEC procesados: {len(capec_df)} entradas.")
print("--- Muestra de CAPECs ---")
print(capec_df.head())


# ----------------------------------------------------
#              PASO 4: UNIR TODO
# ----------------------------------------------------
print("\nUniendo todos los DataFrames...")

# 1. Unir CVEs con los detalles de su CWE
knowledge_base = pd.merge(cve_df, cwe_df, on='cwe_id', how='left')

# 2. Unir el mapeo CWE-CAPEC
knowledge_base = pd.merge(knowledge_base, cwe_capec_df, on='cwe_id', how='left')

# 3. Unir los detalles de CAPEC
knowledge_base = pd.merge(knowledge_base, capec_df, on='capec_id', how='left')

# --- Limpieza Final ---
knowledge_base = knowledge_base.dropna(subset=['capec_id']) 

final_columns = [
    'cve_id', 
    'cvss_score', 
    'description', # Descripción del CVE
    'cwe_id', 
    'cwe_name', 
    'capec_id', 
    'capec_name',
    'capec_description' # Descripción del patrón de ataque
]
knowledge_base = knowledge_base[final_columns].drop_duplicates()

print(f"\n¡Base de Conocimiento Final Creada con {len(knowledge_base)} filas!")
print(knowledge_base.head())

# Guardar tu base de conocimiento en un archivo CSV
output_file = 'cyber_knowledge_base.csv'
knowledge_base.to_csv(output_file, index=False, encoding='utf-8-sig')

print(f"\nBase de conocimiento guardada como: {output_file}")