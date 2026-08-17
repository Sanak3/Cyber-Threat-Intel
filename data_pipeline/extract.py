import os
import time
import requests
from dotenv import load_dotenv

# Carrega as variáveis de ambiente do .env (raiz ou diretório atual)
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))
load_dotenv()


def extrair_dados_nist(total_desejado=10000, max_por_pagina=2000):
    """
    Extrai vulnerabilidades (CVEs) da API v2.0 do NIST NVD utilizando paginação
    inteligente, controle rigoroso de rate limit e estratégia de retry com backoff.

    :param total_desejado: Número total de registros a serem coletados (padrão: 10.000).
    :param max_por_pagina: Limite máximo de registros por requisição da API (máximo NIST: 2.000).
    :return: Dicionário contendo a lista consolidada de vulnerabilidades ou None em caso de falha.
    """
    print(f"[+] [ETL Extract] Iniciando extração escalável do NIST NVD (Alvo: {total_desejado:,} CVEs)...")

    api_key = os.getenv("NIST_API_KEY")

    # Configuração de Headers e Rate Limit conforme disponibilidade da chave
    if api_key:
        headers = {"apiKey": api_key.strip()}
        delay_requisicao = 1.2  # NIST permite ~50 req/30s com chave -> ~0.6s seguro, 1.2s prudente
        print("[+] Chave NIST_API_KEY detectada. Rate limit otimizado ativado (delay: 1.2s).")
    else:
        headers = {}
        delay_requisicao = 6.0  # NIST limita sem chave a ~5 req/30s -> delay de 6.0s
        print("[!] AVISO: NIST_API_KEY não informada. Operando no modo público restrito (delay: 6.0s).")

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    todas_vulnerabilidades = []
    start_index = 0
    total_lotes = (total_desejado + max_por_pagina - 1) // max_por_pagina

    while len(todas_vulnerabilidades) < total_desejado:
        lote_atual = (start_index // max_por_pagina) + 1
        registros_restantes = total_desejado - len(todas_vulnerabilidades)
        results_per_page = min(max_por_pagina, registros_restantes)

        url = f"{base_url}?resultsPerPage={results_per_page}&startIndex={start_index}"
        print(f"\n[*] [ETL Extract] Baixando lote {lote_atual}/{total_lotes} (startIndex={start_index:,} | solicitando {results_per_page} registros)...")

        sucesso_lote = False
        max_tentativas = 3

        for tentativa in range(1, max_tentativas + 1):
            try:
                response = requests.get(url, headers=headers, timeout=45)

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
                    break

                todas_vulnerabilidades.extend(vulnerabilidades_pagina)
                print(f"[+] [ETL Extract] Lote {lote_atual}/{total_lotes} concluído com sucesso: +{qtd_recebida:,} CVEs (Total acumulado: {len(todas_vulnerabilidades):,}/{total_desejado:,}).")

                sucesso_lote = True

                # Se a API já não tiver mais resultados disponíveis no catálogo global
                if start_index + qtd_recebida >= total_api_results:
                    print(f"[*] Base global do NIST esgotada ({total_api_results:,} registros totais). Finalizando paginação.")
                    break

                break  # Sai do loop de retries pois a requisição foi um sucesso

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

        start_index += results_per_page

        # Delay de cortesia para respeito ao rate limit entre páginas sucessivas
        if len(todas_vulnerabilidades) < total_desejado:
            time.sleep(delay_requisicao)

    # Limita rigorosamente ao total desejado
    todas_vulnerabilidades = todas_vulnerabilidades[:total_desejado]
    print(f"\n[+] [ETL Extract] Extração finalizada com sucesso! Total consolidado: {len(todas_vulnerabilidades):,} CVEs.\n")

    return {"vulnerabilities": todas_vulnerabilidades}


if __name__ == "__main__":
    resultado = extrair_dados_nist(total_desejado=10000)