#!/usr/bin/env python3
"""
Gera o arquivo dpipot_types.toml a partir da inspeção dos 4 arquivos CSV de logs do DPIpot:
  - classifier
  - infra
  - pods
  - proxy
"""

import json
import os
import duckdb

types = ['classifier', 'infra', 'pods', 'proxy']

DESCRIPTIONS = {
    '@timestamp': 'Data e hora do evento no padrão ISO-8601 (UTC)',
    '@version': 'Versão do esquema de eventos (Logstash/Filebeat/ECS)',
    '_id': 'Identificador único do documento indexado',
    'category': 'ID numérico da categoria de tráfego classificada pelo nDPI',
    'dst_ip': 'Endereço IP de destino do pacote ou fluxo',
    'dst_port': 'Porta de rede de destino (ex: 22, 80, 443, 30000)',
    'ethertype': 'Código Ethernet do protocolo de rede (ex: 0x0800 para IPv4)',
    'event.original': 'Conteúdo bruto original da mensagem de log antes da formatação',
    'flow_id': 'Identificador único universal (UUID) do fluxo de rede',
    'instance': 'Instância do componente DPIpot emissor (ex: classifier, proxy)',
    'ip_proto': 'Protocolo de camada IP (ex: 6 para TCP, 17 para UDP, 1 para ICMP)',
    'ndpi_app': 'Aplicação ou serviço detectado pelo motor de inspeção nDPI',
    'ndpi_proto': 'Protocolo da camada de aplicação identificado pelo nDPI (ex: SSH, TLS, HTTP, DNS)',
    'payload_len': 'Tamanho da carga útil (payload) em bytes',
    'src_ip': 'Endereço IP de origem do tráfego ou atacante',
    'src_port': 'Porta efêmera ou de origem do tráfego',
    'tcp_flags': 'Flags do cabeçalho TCP observadas (SYN, ACK, RST, FIN, PSH)',
    'transport': 'Protocolo de transporte utilizado (tcp, udp, icmp)',
    'tuple_id': '5-tupla do fluxo de rede (IP_origem:porta-IP_destino:porta-proto)',
    'event_type': 'Tipo semântico do evento (ex: flow, session, auth, command)',
    'ip_version': 'Versão do protocolo de internet (4 para IPv4, 6 para IPv6)',
    'node_name': 'Nome do nó físico ou VM do cluster Kubernetes (ex: dpipot)',
    'pod_name': 'Nome do pod Kubernetes que processou a conexão',
    'tcp_window': 'Tamanho da janela de recepção TCP anunciada (TCP Window Size)',
    'tos': 'Campo Type of Service (ToS) / DSCP do cabeçalho IP',
    'ttl': 'Time to Live (TTL) do pacote IP recebido',
    
    # Proxy / Geo / ASN
    'dst_asn.asn': 'Número do Sistema Autônomo (ASN) de destino',
    'dst_asn.ip': 'Endereço IP consultado para o ASN de destino',
    'dst_asn.network': 'Bloco CIDR de rede correspondente ao ASN de destino',
    'dst_asn.organization_name': 'Nome da organização proprietária do ASN de destino',
    'dst_geo.city_name': 'Nome da cidade do IP de destino',
    'dst_geo.continent_name': 'Continente geográfico do IP de destino',
    'dst_geo.country_iso_code': 'Código ISO de 2 letras do país de destino (ex: BR)',
    'dst_geo.country_name': 'Nome do país de destino (ex: Brazil)',
    'dst_geo.location.lat': 'Latitude geográfica aproximada de destino',
    'dst_geo.location.lon': 'Longitude geográfica aproximada de destino',
    'dst_geo.region_iso_code': 'Código ISO da região ou estado de destino (ex: BR-ES)',
    'dst_geo.region_name': 'Nome do estado ou subdivisão regional de destino',
    'duration_ms': 'Duração total do fluxo de conexão em milissegundos',
    'honeypot': 'Identificador do serviço de honeypot e porta de encaminhamento (ex: cowrie:2222, heralding:80)',
    'payload_dst_b64': 'Payload respondido pelo honeypot codificado em Base64',
    'payload_dst_hex': 'Payload respondido pelo honeypot em formato hexadecimal',
    'payload_dst_text': 'Payload respondido pelo honeypot decodificado em texto UTF-8',
    'payload_src_b64': 'Payload recebido do atacante codificado em Base64',
    'payload_src_hex': 'Payload recebido do atacante em formato hexadecimal',
    'payload_src_text': 'Payload recebido do atacante decodificado em texto legível',
    'per_ip_active': 'Quantidade de conexões simultâneas ativas originadas daquele IP',
    'slots_max': 'Capacidade máxima de conexões simultâneas do proxy',
    'slots_used': 'Número atual de conexões simultâneas em uso no proxy',
    'src_asn.asn': 'Número do Sistema Autônomo (ASN) de origem do atacante',
    'src_asn.ip': 'Endereço IP de origem consultado na base ASN',
    'src_asn.network': 'Bloco CIDR de rede de origem do atacante',
    'src_asn.organization_name': 'Nome da empresa, ISP ou datacenter do atacante',
    'src_geo.city_name': 'Cidade de origem geográfica do atacante',
    'src_geo.continent_name': 'Continente de origem do atacante',
    'src_geo.country_iso_code': 'Código ISO de duas letras do país do atacante',
    'src_geo.country_name': 'País de origem do atacante',
    'src_geo.location.lat': 'Latitude geográfica aproximada da origem',
    'src_geo.location.lon': 'Longitude geográfica aproximada da origem',
    'src_geo.region_iso_code': 'Código da região/estado de origem do atacante',
    'src_geo.region_name': 'Nome do estado ou região da origem do atacante',
    'tags': 'Tags contextuais aplicadas pelo pipeline de ingestão',
    'afpacket_chan_drops': 'Quedas de pacotes na fila de canal do driver AF_PACKET',
    'afpacket_drops': 'Total de pacotes descartados pelo socket AF_PACKET',
    'attack_type': 'Classificação específica do tipo de ataque ou varredura',
    'expected_proto': 'Protocolo esperado na porta segundo a configuração',
    'flows_client_total': 'Contador acumulado de fluxos iniciados por clientes',
    'flows_honeypot_total': 'Contador acumulado de fluxos repassados a honeypots',
    'flow_table_size': 'Número atual de entradas ativas na tabela de fluxos',
    'rtt_ms': 'Tempo de ida e volta estimado (Round-Trip Time) em milissegundos',
    'uptime_sec': 'Tempo de atividade contínua (uptime) do serviço em segundos',
    
    # Pods & Cowrie
    'eventid': 'Código de identificador de evento do honeypot (ex: cowrie.login.failed, cowrie.session.connect)',
    'session': 'Identificador único da sessão de interação aberta pelo honeypot',
    'username': 'Nome de usuário informado na tentativa de autenticação',
    'password': 'Senha informada na tentativa de autenticação',
    'hassh': 'Fingerprint HASSH calculado a partir dos parâmetros de negociação SSH do cliente',
    'hasshAlgorithms': 'String de algoritmos negociados utilizada para calcular o HASSH',
    'kexAlgs': 'Lista de algoritmos de troca de chave (KEX) suportados pelo cliente SSH',
    'keyAlgs': 'Lista de tipos de chaves públicas de servidor aceitas pelo cliente SSH',
    'encCS': 'Lista de algoritmos de criptografia cliente-para-servidor suportados',
    'macCS': 'Lista de algoritmos de integridade (MAC) aceitos pelo cliente SSH',
    'compCS': 'Lista de algoritmos de compressão aceitos pelo cliente',
    'langCS': 'Configuração de idiomas aceitos pelo cliente SSH',
    'executed_command': 'Comando de terminal extraído executado pelo invasor',
    'sensor': 'Nome do sensor ou pod honeypot que capturou a sessão',
    'protocol': 'Protocolo da sessão do honeypot (ex: ssh, telnet, rdp, http)',
    'stream': 'Canal de saída do container (stdout ou stderr)',
    'timestamp': 'Timestamp do evento emitido internamente pelo honeypot',
    'uuid': 'Identificador único do evento no honeypot',
    'message': 'Mensagem descritiva de log do honeypot ou comando',
    
    # Infra & Filebeat / Kubernetes
    'container.id': 'ID hexadecimal do container Docker/containerd no Kubernetes',
    'container.image.name': 'Nome da imagem de container utilizada (ex: filebeat, cowrie, proxy)',
    'container.runtime': 'Runtime de containers em execução (ex: containerd)',
    'ecs.version': 'Versão da especificação Elastic Common Schema (ECS)',
    'finished': 'Sinaliza se a coleta do arquivo pelo harvester foi finalizada',
    'harvester_id': 'UUID do leitor de arquivos do Filebeat (harvester)',
    'host.name': 'Nome do host onde o agente de coleta está rodando',
    'input_id': 'ID do input de coleta de logs configurado no Filebeat',
    'kubernetes.container.name': 'Nome do container definido no manifesto Kubernetes',
    'kubernetes.daemonset.name': 'Nome do DaemonSet Kubernetes correspondente',
    'kubernetes.labels.app': 'Label app do Kubernetes associada à carga de trabalho',
    'kubernetes.namespace': 'Namespace do Kubernetes onde o pod está alocado (ex: dpipot)',
    'kubernetes.node.hostname': 'Hostname do nó do cluster Kubernetes',
    'kubernetes.pod.ip': 'Endereço IP interno atribuído ao pod pelo CNI do Kubernetes',
    'kubernetes.pod.name': 'Nome do pod instanciado no cluster Kubernetes',
    'kubernetes.pod.uid': 'Identificador único universal (UID) do pod no Kubernetes',
    'log.file.path': 'Caminho absoluto do arquivo de log no nó do cluster',
    'log.level': 'Nível de severidade do log (ex: info, error, warning, debug)',
    'log.offset': 'Posição em bytes (offset) no arquivo de log de origem',
    'service.name': 'Nome do serviço associado à emissão do log'
}

type_titles = {
    'classifier': ('Classificador nDPI', 'Logs de classificação profunda de tráfego de rede (nDPI / DPIpot Classifier) capturados na borda.'),
    'infra': ('Infraestrutura & Orquestração', 'Logs operacionais de infraestrutura Kubernetes, agentes Filebeat e telemetria dos nós.'),
    'pods': ('Pods & Honeypots (Cowrie/Heralding)', 'Logs de interação direta dos invasores com os honeypots de alta interatividade (SSH, Telnet, RDP).'),
    'proxy': ('Proxy MITM & Fluxos de Rede', 'Logs de fluxos capturados pelo proxy transparente (TPROXY) com enriquecimento GeoIP/ASN e telemetria.')
}

def escape_toml_string(s: str) -> str:
    out = []
    for ch in s:
        code = ord(ch)
        if ch == '\\':
            out.append('\\\\')
        elif ch == '"':
            out.append('\\"')
        elif ch == '\t':
            out.append('\\t')
        elif ch in ('\n', '\r'):
            out.append(' ')
        elif code < 32 or (127 <= code <= 159):
            out.append(f'\\u{code:04x}')
        else:
            out.append(ch)
    return ''.join(out)

def main():
    con = duckdb.connect()
    toml_lines = [
        '# =====================================================================',
        '# DPIpot-Analytics - Dicionário de Dados e Esquema dos Tipos de Logs',
        '# Configuração oficial dos 4 tipos de logs do DPIpot:',
        '#   • classifier - Classificador nDPI de pacotes e fluxos',
        '#   • infra      - Infraestrutura Kubernetes e métricas de nós/pods',
        '#   • pods       - Sessões e credenciais nos honeypots (Cowrie, etc.)',
        '#   • proxy      - Proxy MITM TPROXY com telemetria e enriquecimento GeoIP',
        '#',
        '# Este arquivo pode ser editado livremente para personalizar tipos,',
        '# exemplos e descrições. A TUI exibe e recarrega estas definições.',
        '# =====================================================================',
        ''
    ]

    for t in types:
        label, desc = type_titles[t]
        csv_file = f'logs/dpipot-{t}-2026.07.27.csv'
        
        describe = con.execute(f"DESCRIBE SELECT * FROM read_csv('{csv_file}', ignore_errors=true, sample_size=20000);").fetchall()
        sample_rows = con.execute(f"SELECT * FROM read_csv('{csv_file}', ignore_errors=true) LIMIT 500;").fetchdf()
        
        toml_lines.append(f'[{t}]')
        toml_lines.append(f'name = "{t}"')
        toml_lines.append(f'label = "{label}"')
        toml_lines.append(f'description = "{desc}"')
        toml_lines.append(f'total_columns = {len(describe)}')
        toml_lines.append('')
        
        for row in describe:
            col_name = row[0]
            col_type = row[1]
            
            # Formatar tipo limpo
            if 'TIMESTAMP' in col_type:
                clean_type = 'TIMESTAMP'
            elif 'BIGINT' in col_type or 'INTEGER' in col_type:
                clean_type = 'INTEGER'
            elif 'DOUBLE' in col_type or 'FLOAT' in col_type:
                clean_type = 'DOUBLE'
            elif 'BOOLEAN' in col_type:
                clean_type = 'BOOLEAN'
            else:
                clean_type = 'VARCHAR'
                
            sample_val = ''
            if col_name in sample_rows:
                series = sample_rows[col_name].dropna()
                for v in series:
                    s_str = str(v).strip()
                    if s_str and s_str.lower() != 'nan':
                        sample_val = s_str[:70]
                        break
                        
            # Buscar descrição
            description = DESCRIPTIONS.get(col_name)
            if not description:
                if col_name.startswith('kubernetes.'):
                    sub = col_name.replace('kubernetes.', '')
                    description = f'Metadado do Kubernetes para {sub}'
                elif col_name.startswith('monitoring.metrics.'):
                    sub = col_name.replace('monitoring.metrics.', '')
                    description = f'Métrica interna de monitoramento ({sub})'
                elif col_name.startswith('src_geo.'):
                    sub = col_name.split('.')[-1]
                    description = f'Geolocalização MaxMind do IP atacante ({sub})'
                elif col_name.startswith('dst_geo.'):
                    sub = col_name.split('.')[-1]
                    description = f'Geolocalização MaxMind do IP de destino ({sub})'
                elif col_name.startswith('src_asn.'):
                    sub = col_name.split('.')[-1]
                    description = f'Sistema Autônomo (ASN) da rede do atacante ({sub})'
                elif col_name.startswith('dst_asn.'):
                    sub = col_name.split('.')[-1]
                    description = f'Sistema Autônomo (ASN) da rede de destino ({sub})'
                elif col_name.startswith('heralding.'):
                    sub = col_name.split('.')[-1]
                    description = f'Propriedade de captura do honeypot Heralding ({sub})'
                elif 'payload' in col_name:
                    description = f'Dados da carga útil de rede ({col_name})'
                else:
                    description = f'Campo de registro de log ({col_name})'
                    
            toml_lines.append(f'[[{t}.columns]]')
            toml_lines.append(f'name = "{col_name}"')
            toml_lines.append(f'type = "{clean_type}"')
            toml_lines.append(f'example = "{escape_toml_string(sample_val)}"')
            toml_lines.append(f'description = "{escape_toml_string(description)}"')
            toml_lines.append('')

    out_file = 'dpipot_types.toml'
    with open(out_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(toml_lines))
    print(f'Sucesso: {out_file} gerado com sucesso!')

if __name__ == '__main__':
    main()
