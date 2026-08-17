import numpy as np


def extrair_metricas_cvss(metrics):
    """
    Extrai score e severidade com cadeia de fallback:
    CVSS v3.1 -> CVSS v3.0 -> CVSS v2.0 -> Default (0.0, 'UNKNOWN').
    """
    if not isinstance(metrics, dict):
        return 0.0, "UNKNOWN"

    # 1. Tentativa com CVSS v3.1 (Padrão mais recente)
    v31_list = metrics.get("cvssMetricV31", [])
    if v31_list and isinstance(v31_list, list):
        cvss_data = v31_list[0].get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity")
        if score is not None:
            return float(score), str(severity or "UNKNOWN").upper()

    # 2. Tentativa com CVSS v3.0
    v30_list = metrics.get("cvssMetricV30", [])
    if v30_list and isinstance(v30_list, list):
        cvss_data = v30_list[0].get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity")
        if score is not None:
            return float(score), str(severity or "UNKNOWN").upper()

    # 3. Tentativa com CVSS v2.0 (Legado)
    v2_list = metrics.get("cvssMetricV2", [])
    if v2_list and isinstance(v2_list, list):
        cvss_data = v2_list[0].get("cvssData", {})
        score = cvss_data.get("baseScore")
        # No CVSS v2 da NVD, baseSeverity pode estar no nível superior do item ou dentro de cvssData
        severity = v2_list[0].get("baseSeverity") or cvss_data.get("baseSeverity")
        if score is not None:
            score_float = float(score)
            if not severity:
                # Classificação canônica CVSS v2
                if score_float >= 7.0:
                    severity = "HIGH"
                elif score_float >= 4.0:
                    severity = "MEDIUM"
                elif score_float > 0.0:
                    severity = "LOW"
                else:
                    severity = "UNKNOWN"
            return score_float, str(severity).upper()

    return 0.0, "UNKNOWN"


def sanitizar_texto(texto):
    """
    Sanitiza strings para inserção segura no banco de dados,
    removendo caracteres nulos (\x00) e espaços excessivos.
    """
    if not texto:
        return "Sem descrição disponível."
    # Remove bytes nulos incompatíveis com tipos TEXT no PostgreSQL
    texto_limpo = str(texto).replace('\x00', '')
    return texto_limpo.strip()


def transformar_dados(dados_brutos):
    """
    Processa e normaliza vulnerabilidades em memória com NumPy,
    calculando matriz vetorial de risco e estatísticas agregadas.

    :param dados_brutos: Dicionário contendo lista de 'vulnerabilities' do NIST.
    :return: Lista de dicionários normalizados prontos para carga no banco.
    """
    print("[+] [ETL Transform] Iniciando transformação e análise matricial com NumPy...")

    vulnerabilidades_input = dados_brutos.get("vulnerabilities", []) if dados_brutos else []
    total_extraido = len(vulnerabilidades_input)

    if total_extraido == 0:
        print("[-] [ETL Transform] Nenhum registro fornecido para transformação.")
        return []

    vulnerabilidades_limpas = []
    notas_cvss = []

    for item in vulnerabilidades_input:
        cve = item.get("cve", {})
        id_cve = cve.get("id", "UNKNOWN").strip()

        # Extração de descrição em inglês ('en')
        descricoes = cve.get("descriptions", [])
        descricao_raw = next(
            (d.get("value") for d in descricoes if isinstance(d, dict) and d.get("lang") == "en"),
            next((d.get("value") for d in descricoes if isinstance(d, dict)), "Sem descrição disponível.")
        )
        descricao = sanitizar_texto(descricao_raw)

        # Extração de métricas de severidade com fallback em cascata
        metrics = cve.get("metrics", {})
        nota, severidade = extrair_metricas_cvss(metrics)

        # Fallback de severidade baseado na nota se veio UNKNOWN mas nota > 0
        if (not severidade or severidade == "UNKNOWN") and nota > 0.0:
            if nota >= 9.0:
                severidade = "CRITICAL"
            elif nota >= 7.0:
                severidade = "HIGH"
            elif nota >= 4.0:
                severidade = "MEDIUM"
            else:
                severidade = "LOW"

        vulnerabilidades_limpas.append({
            "id_cve": id_cve,
            "descricao": descricao,
            "nota_cvss": nota,
            "severidade": severidade
        })

        if nota > 0.0:
            notas_cvss.append(nota)

    # --------------------------------------------------------------------------
    # ANÁLISE VETORIAL E ESTATÍSTICA DE RISCO (NUMPY ENGINE)
    # --------------------------------------------------------------------------
    array_notas = np.array(notas_cvss, dtype=np.float64)
    total_com_nota = len(array_notas)
    aguardando_analise = total_extraido - total_com_nota

    print("\n" + "=" * 65)
    print("        INTELIGÊNCIA DE AMEAÇAS // MATRIZ DE RISCO (NumPy)       ")
    print("=" * 65)
    print(f"[*] Total de CVEs Processados:       {total_extraido:,}")
    print(f"[*] CVEs Avaliados com CVSS Score:   {total_com_nota:,} ({(total_com_nota / total_extraido * 100):.1f}%)")
    print(f"[*] CVEs Pendentes de Análise NIST:  {aguardando_analise:,} ({(aguardando_analise / total_extraido * 100):.1f}%)")
    print("-" * 65)

    if total_com_nota > 0:
        media_risco = float(np.mean(array_notas))
        desvio_padrao = float(np.std(array_notas))
        risco_maximo = float(np.max(array_notas))
        risco_minimo = float(np.min(array_notas))

        # Indexação booleana vetorial de alta performance
        criticas = int(np.sum(array_notas >= 9.0))
        altas = int(np.sum((array_notas >= 7.0) & (array_notas < 9.0)))
        medias = int(np.sum((array_notas >= 4.0) & (array_notas < 7.0)))
        baixas = int(np.sum((array_notas > 0.0) & (array_notas < 4.0)))

        print(f"[*] Média Global de Risco (CVSS):    {media_risco:.2f} (±{desvio_padrao:.2f})")
        print(f"[*] Pior Score Detectado (Máximo):   {risco_maximo:.1f}")
        print(f"[*] Menor Score Detectado (Mínimo):  {risco_minimo:.1f}")
        print("-" * 65)
        print("[*] Distribuição de Severidade:")
        print(f"    - [CRÍTICO] (9.0 - 10.0): {criticas:6,} ameaças ({(criticas / total_com_nota * 100):.1f}%)")
        print(f"    - [ALTO]    (7.0 - 8.9):  {altas:6,} ameaças ({(altas / total_com_nota * 100):.1f}%)")
        print(f"    - [MÉDIO]   (4.0 - 6.9):  {medias:6,} ameaças ({(medias / total_com_nota * 100):.1f}%)")
        print(f"    - [BAIXO]   (0.1 - 3.9):  {baixas:6,} ameaças ({(baixas / total_com_nota * 100):.1f}%)")
    else:
        print("[!] Nenhuma métrica CVSS válida encontrada nos registros fornecidos.")

    print("=" * 65 + "\n")

    return vulnerabilidades_limpas