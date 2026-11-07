import os
import time
from datetime import datetime, timezone, timedelta
import requests
from dotenv import load_dotenv

# Carrega as variáveis de ambiente do .env (raiz ou diretório atual)
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))
load_dotenv()


def _extrair_catalogo_kev_nist(session, base_url, delay_requisicao):
    """
    Baixa o catálogo completo de vulnerabilidades confirmadas no CISA KEV (?hasKev)
    diretamente da API v2.0 do NIST NVD (~1.2k registros em 1 lote de 2.000),
    garantindo que ameaças de anos anteriores exploradas ativamente não fiquem fora do offset recente.
    """
    kev_vulns = []
    kev_offset = 0
    results_per_page = 2000

    print("[*] [ETL Extract] Sincronizando catálogo complementar CISA KEV (?hasKev) no NIST NVD...")
    while True:
        url_kev = f"{base_url}?noRejected&hasKev&resultsPerPage={results_per_page}&startIndex={kev_offset}"
        sucesso_pagina = False

        for tentativa in range(1, 4):
            try:
                res = session.get(url_kev, timeout=45)
                if res.status_code == 429:
                    time.sleep(30)
                    continue
                if res.status_code in [503, 504]:
                    time.sleep(2 ** tentativa * 3)
                    continue

                res.raise_for_status()
                payload = res.json()
                pagina = payload.get("vulnerabilities", [])
                total_kev = payload.get("totalResults", 0)

                kev_vulns.extend(pagina)
                sucesso_pagina = True

                if not pagina or kev_offset + len(pagina) >= total_kev:
                    print(f"[+] [ETL Extract] Catálogo CISA KEV sincronizado: {len(kev_vulns):,} CVEs ativas obtidas.")
                    return kev_vulns

                kev_offset += len(pagina)
                time.sleep(delay_requisicao)
                break
            except requests.exceptions.RequestException as err:
                espera = 2 ** tentativa * 2
                print(f"[!] [ETL Extract] Aviso ao consultar ?hasKev ({err}). Retry em {espera}s ({tentativa}/3)...")
                time.sleep(espera)

        if not sucesso_pagina:
            print("[!] [ETL Extract] Não foi possível concluir a página complementar de KEV. Prosseguindo com lote principal.")
            break

    return kev_vulns


def extrair_scores_epss(cve_ids, chunk_size=100, timeout=15):
    """
    Consulta em lote a API pública gratuita do FIRST.org EPSS (Exploit Prediction Scoring System)
    retornando probabilidade de exploração em 30 dias (epss) e percentil para cada CVE.
    """
    ids_unicos = [str(c).strip() for c in dict.fromkeys(cve_ids or []) if str(c).strip().startswith("CVE-")]
    if not ids_unicos:
        return {}

    epss_url = "https://api.first.org/data/v1/epss"
    mapa_epss = {}
    falhas_consecutivas = 0
    chunk_seguro = max(1, min(int(chunk_size), 100))
    total_lotes = (len(ids_unicos) + chunk_seguro - 1) // chunk_seguro

    print(f"[+] [EPSS Engine] Enriquecendo {len(ids_unicos):,} CVEs na API FIRST.org ({total_lotes} lotes)...")

    session = requests.Session()
    session.headers.update({"User-Agent": "CyberThreatIntel-Bot/2.0 (EPSS Enrichment)"})

    try:
        for i in range(0, len(ids_unicos), chunk_seguro):
            lote_ids = ids_unicos[i:i + chunk_seguro]
            try:
                res = session.get(
                    epss_url,
                    params={"cve": ",".join(lote_ids)},
                    timeout=timeout
                )
                if res.status_code != 200:
                    falhas_consecutivas += 1
                    if falhas_consecutivas >= 3:
                        print("[!] [EPSS Engine] API FIRST.org indisponível no momento. Seguindo com scores parciais.")
                        break
                    continue

                falhas_consecutivas = 0
                dados = res.json().get("data", [])
                for item in dados:
                    cve_id = item.get("cve")
                    if not cve_id:
                        continue
                    try:
                        score = max(0.0, min(1.0, float(item.get("epss", 0.0))))
                        percentile = max(0.0, min(1.0, float(item.get("percentile", 0.0))))
                        mapa_epss[cve_id] = {
                            "epss": round(score, 5),
                            "percentile": round(percentile, 5)
                        }
                    except (TypeError, ValueError):
                        continue
            except requests.exceptions.RequestException:
                falhas_consecutivas += 1
                if falhas_consecutivas >= 3:
                    print("[!] [EPSS Engine] Timeout/rede ao consultar FIRST.org. Prosseguindo sem bloquear o ETL.")
                    break
    finally:
        session.close()

    print(f"[+] [EPSS Engine] Enriquecimento concluído: {len(mapa_epss):,} CVEs com probabilidade EPSS mapeada.")
    return mapa_epss


def extrair_dados_nist(
    total_desejado=20000,
    max_por_pagina=2000,
    buscar_mais_recentes=True,
    janela_dias=None,
    incluir_catalogo_kev=True
):
    """
    Extrai vulnerabilidades (CVEs) da API v2.0 do NIST NVD utilizando:
    - Descoberta inteligente do final do catálogo (totalResults - total_desejado) ou filtro
      de janela temporal (lastModStartDate / lastModEndDate de até 90-120 dias) para extrair
      as CVEs mais recentes em vez de registros legados de 1999.
    - Sessão persistente (requests.Session) para reaproveitamento de conexões e handshake TLS/SSL.
    - User-Agent customizado para identificação clara no tráfego HTTP.
    - Paginação inteligente até atingir o total desejado de registros.
    - Controle rigoroso de rate limit com retries exponenciais e tratamento de 429/503/504.

    :param total_desejado: Número total de registros a serem coletados (padrão: 20.000).
    :param max_por_pagina: Limite máximo de registros por requisição da API (máximo NIST: 2.000).
    :param buscar_mais_recentes: Se True, inicia a busca pelas CVEs mais recentes do catálogo.
    :param janela_dias: Se informado (ex: 90), usa filtro de data no formato ISO da NIST v2.0 (máx 120 dias).
    :return: Dicionário contendo a lista consolidada de vulnerabilidades ou None em caso de falha.
    """
    print(f"[+] [ETL Extract] Iniciando extração escalável do NIST NVD (Alvo: {total_desejado:,} CVEs)...")

    api_key = os.getenv("NIST_API_KEY")

    # Configuração de Headers Globais e User-Agent
    custom_headers = {
        "User-Agent": "CyberThreatIntel-Bot/2.0 (Security Intelligence Pipeline)"
    }

    if api_key:
        custom_headers["apiKey"] = api_key.strip()
        delay_requisicao = 1.2  # ~50 req/30s com chave -> 1.2s de intervalo seguro
        print("[+] Chave NIST_API_KEY detectada. Rate limit otimizado ativado (delay: 1.2s).")
    else:
        delay_requisicao = 6.0  # ~5 req/30s sem chave -> 6.0s de intervalo
        print("[!] AVISO: NIST_API_KEY não informada. Operando no modo público restrito (delay: 6.0s).")

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    todas_vulnerabilidades = []
    start_index = 0

    # Inicializa sessão persistente com pooling de conexões
    session = requests.Session()
    session.headers.update(custom_headers)

    # Parâmetros de data para sincronização incremental (respeitando limite de 120 dias da API v2.0)
    date_params = ""
    if janela_dias:
        dias_validos = max(1, min(int(janela_dias), 120))
        agora = datetime.now(timezone.utc)
        inicio_janela = agora - timedelta(days=dias_validos)
        
        # Formato canônico NIST v2.0: YYYY-MM-DDTHH:mm:ss.000
        start_str = inicio_janela.strftime("%Y-%m-%dT%H:%M:%S.000")
        end_str = agora.strftime("%Y-%m-%dT%H:%M:%S.000")
        date_params = f"&lastModStartDate={start_str}&lastModEndDate={end_str}"
        print(f"[+] [ETL Extract] Filtro incremental ativado: janela de {dias_validos} dias ({start_str} até {end_str}).")

    try:
        # Se buscar_mais_recentes estiver ativo e sem filtro de janela de datas,
        # calcula startIndex a partir do totalResults global da API do NIST (com retry resiliente)
        if buscar_mais_recentes and not date_params:
            print("[*] [ETL Extract] Consultando metadados do catálogo global para calcular offset das vulnerabilidades mais recentes...")
            descoberta_ok = False
            for tentativa_disc in range(1, 4):
                try:
                    discovery_res = session.get(f"{base_url}?noRejected&resultsPerPage=1", timeout=30)
                    if discovery_res.status_code == 429:
                        print(f"[-] [RATE LIMIT 429] Aguardando 30s na descoberta de offset (Tentativa {tentativa_disc}/3)...")
                        time.sleep(30)
                        continue
                    if discovery_res.status_code in [503, 504]:
                        espera = 2 ** tentativa_disc * 3
                        print(f"[-] [HTTP {discovery_res.status_code}] NIST ocupado na descoberta. Backoff de {espera}s (Tentativa {tentativa_disc}/3)...")
                        time.sleep(espera)
                        continue

                    discovery_res.raise_for_status()
                    total_global = discovery_res.json().get("totalResults", 0)
                    if total_global > total_desejado:
                        start_index = total_global - total_desejado
                        print(f"[+] [ETL Extract] Catálogo possui {total_global:,} CVEs. Iniciando no offset {start_index:,} para baixar os {total_desejado:,} registros mais recentes.")
                    else:
                        print(f"[*] [ETL Extract] Catálogo possui {total_global:,} registros. Iniciando de startIndex=0.")
                    descoberta_ok = True
                    time.sleep(delay_requisicao)
                    break
                except requests.exceptions.RequestException as e_disc:
                    espera = 2 ** tentativa_disc * 2
                    print(f"[!] [ETL Extract] Erro ao consultar offset recente ({e_disc}). Retry em {espera}s ({tentativa_disc}/3)...")
                    time.sleep(espera)

            if not descoberta_ok:
                print("[-] [FALHA CRÍTICA] Não foi possível determinar o offset recente do NIST. Abortando para evitar ingestão de registros legados de 1999.")
                return None

        total_lotes = (total_desejado + max_por_pagina - 1) // max_por_pagina

        while len(todas_vulnerabilidades) < total_desejado:
            lote_atual = (len(todas_vulnerabilidades) // max_por_pagina) + 1
            registros_restantes = total_desejado - len(todas_vulnerabilidades)
            results_per_page = min(max_por_pagina, registros_restantes)

            url = f"{base_url}?noRejected&resultsPerPage={results_per_page}&startIndex={start_index}{date_params}"
            print(f"\n[*] [ETL Extract] Baixando lote {lote_atual}/{total_lotes} (startIndex={start_index:,} | solicitando {results_per_page} registros)...")

            sucesso_lote = False
            catalogo_esgotado = False
            qtd_recebida = 0
            max_tentativas = 3

            for tentativa in range(1, max_tentativas + 1):
                try:
                    response = session.get(url, timeout=45)

                    # Tratamento explícito de Rate Limit (HTTP 429)
                    if response.status_code == 429:
                        print(f"[-] [RATE LIMIT 429] Limite de requisições atingido. Aguardando 30s para retry (Tentativa {tentativa}/{max_tentativas})...")
                        time.sleep(30)
                        continue

                    # Tratamento de sobrecarga no servidor NIST (503 / 504)
                    if response.status_code in [503, 504]:
                        tempo_espera = 2 ** tentativa * 3
                        print(f"[-] [HTTP {response.status_code}] Servidor NIST ocupado. Aguardando backoff de {tempo_espera}s (Tentativa {tentativa}/{max_tentativas})...")
                        time.sleep(tempo_espera)
                        continue

                    response.raise_for_status()
                    dados = response.json()

                    vulnerabilidades_pagina = dados.get("vulnerabilities", [])
                    qtd_recebida = len(vulnerabilidades_pagina)
                    total_api_results = dados.get("totalResults", 0)

                    if qtd_recebida == 0:
                        print(f"[!] [ETL Extract] Nenhum registro adicional retornado pela API no startIndex={start_index}.")
                        sucesso_lote = True
                        catalogo_esgotado = True
                        break

                    todas_vulnerabilidades.extend(vulnerabilidades_pagina)
                    print(f"[+] [ETL Extract] Lote {lote_atual}/{total_lotes} concluído com sucesso: +{qtd_recebida:,} CVEs (Total acumulado: {len(todas_vulnerabilidades):,}/{total_desejado:,}).")

                    sucesso_lote = True

                    # Se a API esgotar os resultados do catálogo global
                    if start_index + qtd_recebida >= total_api_results:
                        print(f"[*] Base global do NIST esgotada ({total_api_results:,} registros totais). Finalizando paginação.")
                        catalogo_esgotado = True
                        break

                    break  # Sucesso no lote, avança para o próximo

                except requests.exceptions.Timeout:
                    tempo_espera = 2 ** tentativa * 2
                    print(f"[-] [TIMEOUT] Tempo de resposta excedido. Retry em {tempo_espera}s (Tentativa {tentativa}/{max_tentativas})...")
                    time.sleep(tempo_espera)
                except requests.exceptions.RequestException as err:
                    tempo_espera = 2 ** tentativa * 2
                    print(f"[-] [ERRO DE REDE] {err}. Retry em {tempo_espera}s (Tentativa {tentativa}/{max_tentativas})...")
                    time.sleep(tempo_espera)
                except Exception as e:
                    print(f"[-] [ERRO INESPERADO] {e}")
                    break

            if not sucesso_lote:
                print(f"[-] [FALHA CRÍTICA] Não foi possível baixar o lote {lote_atual} após {max_tentativas} tentativas.")
                if len(todas_vulnerabilidades) == 0:
                    return None
                print(f"[!] Prosseguindo com os {len(todas_vulnerabilidades):,} registros coletados até o momento.")
                break

            if catalogo_esgotado:
                break

            start_index += qtd_recebida

            # Delay entre requisições para respeito ao rate limit
            if len(todas_vulnerabilidades) < total_desejado:
                time.sleep(delay_requisicao)

        # Limita o lote sequencial ao total desejado antes de mesclar o catálogo complementar CISA KEV
        todas_vulnerabilidades = todas_vulnerabilidades[:total_desejado]

        if incluir_catalogo_kev and buscar_mais_recentes and not date_params and len(todas_vulnerabilidades) > 0:
            time.sleep(delay_requisicao)
            kev_vulns = _extrair_catalogo_kev_nist(session, base_url, delay_requisicao)
            if kev_vulns:
                ids_presentes = {
                    v.get("cve", {}).get("id")
                    for v in todas_vulnerabilidades
                    if isinstance(v, dict) and v.get("cve", {}).get("id")
                }
                novos_kev = 0
                for kv in kev_vulns:
                    kid = kv.get("cve", {}).get("id") if isinstance(kv, dict) else None
                    if kid and kid not in ids_presentes:
                        todas_vulnerabilidades.append(kv)
                        ids_presentes.add(kid)
                        novos_kev += 1
                print(f"[+] [ETL Extract] Mesclagem KEV concluída: +{novos_kev:,} CVEs KEV históricas incorporadas ao dataset.")

    finally:
        session.close()

    print(f"\n[+] [ETL Extract] Extração finalizada com sucesso! Total consolidado: {len(todas_vulnerabilidades):,} CVEs.\n")

    return {"vulnerabilities": todas_vulnerabilidades}


if __name__ == "__main__":
    resultado = extrair_dados_nist(total_desejado=20000)