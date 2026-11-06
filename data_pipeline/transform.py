import numpy as np


def normalizar_severidade_cvss(score_float, severity_raw=None):
    """
    Normaliza o rótulo de severidade pela escala canônica CVSS v3/v4,
    garantindo que notas >= 9.0 (inclusive vindas do CVSS v2 legado onde o teto era HIGH)
    sejam classificadas como CRITICAL para manter 100% de paridade com os KPIs e filtros SQL.
    """
    if score_float >= 9.0:
        return "CRITICAL"
    if score_float >= 7.0:
        return "HIGH"
    if score_float >= 4.0:
        return "MEDIUM"
    if score_float > 0.0:
        return "LOW"
    if severity_raw and str(severity_raw).upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return str(severity_raw).upper()
    return "UNKNOWN"


def _selecionar_metrica_preferencial(metric_list):
    """Prioriza a avaliação Primary (NIST NVD) sobre Secondary (CNA/ADP) quando disponível."""
    if not metric_list or not isinstance(metric_list, list):
        return None
    primaria = next((m for m in metric_list if isinstance(m, dict) and m.get("type") == "Primary"), None)
    return primaria or metric_list[0]


def extrair_metricas_cvss(metrics):
    """
    Extrai score e severidade com cadeia de fallback:
    CVSS v3.1 -> CVSS v4.0 -> CVSS v3.0 -> CVSS v2.0 -> Default (0.0, 'UNKNOWN').
    """
    if not isinstance(metrics, dict):
        return 0.0, "UNKNOWN"

    # 1. Tentativa com CVSS v3.1
    v31_item = _selecionar_metrica_preferencial(metrics.get("cvssMetricV31", []))
    if v31_item:
        cvss_data = v31_item.get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity")
        if score is not None:
            score_float = float(score)
            return score_float, normalizar_severidade_cvss(score_float, severity)

    # 2. Tentativa com CVSS v4.0 (Recente em CVEs de 2024-2026)
    v40_item = _selecionar_metrica_preferencial(metrics.get("cvssMetricV40", []))
    if v40_item:
        cvss_data = v40_item.get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity")
        if score is not None:
            score_float = float(score)
            return score_float, normalizar_severidade_cvss(score_float, severity)

    # 3. Tentativa com CVSS v3.0
    v30_item = _selecionar_metrica_preferencial(metrics.get("cvssMetricV30", []))
    if v30_item:
        cvss_data = v30_item.get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity")
        if score is not None:
            score_float = float(score)
            return score_float, normalizar_severidade_cvss(score_float, severity)

    # 4. Tentativa com CVSS v2.0 (Legado - promove score >= 9.0 de HIGH para CRITICAL)
    v2_item = _selecionar_metrica_preferencial(metrics.get("cvssMetricV2", []))
    if v2_item:
        cvss_data = v2_item.get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = v2_item.get("baseSeverity") or cvss_data.get("baseSeverity")
        if score is not None:
            score_float = float(score)
            return score_float, normalizar_severidade_cvss(score_float, severity)

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
    rejeitadas_ignoradas = 0

    for item in vulnerabilidades_input:
        cve = item.get("cve", {})
        id_cve = cve.get("id", "UNKNOWN").strip()

        # Defesa em profundidade: descarta CVEs com status Rejected
        vuln_status = str(cve.get("vulnStatus") or "").strip().upper()
        if vuln_status == "REJECTED":
            rejeitadas_ignoradas += 1
            continue

        # Extração de descrição em inglês ('en')
        descricoes = cve.get("descriptions", [])
        descricao_raw = next(
            (d.get("value") for d in descricoes if isinstance(d, dict) and d.get("lang") == "en"),
            next((d.get("value") for d in descricoes if isinstance(d, dict)), "Sem descrição disponível.")
        )
        descricao = sanitizar_texto(descricao_raw)

        if descricao.startswith("** REJECT **") or descricao.startswith("Rejected reason:"):
            rejeitadas_ignoradas += 1
            continue

        # Extração de métricas de severidade com fallback em cascata
        metrics = cve.get("metrics", {})
        nota, severidade = extrair_metricas_cvss(metrics)

        # Normalização canônica garantida para alinhar 100% KPIs SQL e filtros da tabela
        severidade = normalizar_severidade_cvss(nota, severidade)

        # Extração de datas oficiais do NIST
        data_publicacao = cve.get("published")
        data_modificacao = cve.get("lastModified")

        # Extração de fraqueza estruturada (CWE)
        cwe_extraido = "NVD-CWE-noinfo"
        for w in cve.get("weaknesses", []):
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-") and val not in ["NVD-CWE-noinfo", "NVD-CWE-Other"]:
                    cwe_extraido = val
                    break
            if cwe_extraido != "NVD-CWE-noinfo":
                break

        # Extração de produto e fabricante via CPE estruturado (Configurations)
        cpe_vendor = None
        cpe_product = None
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    crit = match.get("criteria", "")
                    if crit.startswith("cpe:2.3:"):
                        parts = crit.split(":")
                        if len(parts) > 5:
                            cpe_vendor = parts[3]
                            cpe_product = parts[4]
                            break
                if cpe_vendor:
                    break
            if cpe_vendor:
                break

        # Catálogo CISA KEV (Known Exploited Vulnerabilities - Exploited in the Wild)
        cisa_kev = bool(cve.get("cisaExploitAdd"))

        vulnerabilidades_limpas.append({
            "id_cve": id_cve,
            "descricao": descricao,
            "nota_cvss": nota,
            "severidade": severidade,
            "data_publicacao": data_publicacao,
            "data_modificacao": data_modificacao,
            "cwe": cwe_extraido,
            "cpe_vendor": cpe_vendor,
            "cpe_product": cpe_product,
            "cisa_kev": cisa_kev
        })

        if nota > 0.0:
            notas_cvss.append(nota)

    total_validos = len(vulnerabilidades_limpas)
    if rejeitadas_ignoradas > 0:
        print(f"[*] [ETL Transform] {rejeitadas_ignoradas:,} CVEs revogadas/rejeitadas descartadas.")

    if total_validos == 0:
        print("[-] [ETL Transform] Nenhum registro válido restante após filtragem.")
        return []

    # --------------------------------------------------------------------------
    # ANÁLISE VETORIAL E ESTATÍSTICA DE RISCO (NUMPY ENGINE)
    # --------------------------------------------------------------------------
    array_notas = np.array(notas_cvss, dtype=np.float64)
    total_com_nota = len(array_notas)
    aguardando_analise = total_validos - total_com_nota

    print("\n" + "=" * 65)
    print("        INTELIGÊNCIA DE AMEAÇAS // MATRIZ DE RISCO (NumPy)       ")
    print("=" * 65)
    print(f"[*] Total de CVEs Válidos:           {total_validos:,}")
    print(f"[*] CVEs Avaliados com CVSS Score:   {total_com_nota:,} ({(total_com_nota / total_validos * 100):.1f}%)")
    print(f"[*] CVEs Pendentes de Análise NIST:  {aguardando_analise:,} ({(aguardando_analise / total_validos * 100):.1f}%)")
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

    # --------------------------------------------------------------------------
    # MOTOR DE INTELIGÊNCIA ARTIFICIAL E GRAFOS (ML ENGINE)
    # --------------------------------------------------------------------------
    print("[+] [ML Engine] Iniciando enriquecimento de primitivas táticas e clustering...")
    try:
        from ml_engine.primitives import enriquecer_vulnerabilidades
        from ml_engine.clusterizer import CVEClusterizer, MODEL_FILE
        from ml_engine.chain_detector import ExploitChainDetector
        from ml_engine.writeup_builder import WriteupBuilder

        # 1. Enriquecimento de Primitivas e Tecnologia
        df = enriquecer_vulnerabilidades(vulnerabilidades_limpas)

        # 2. Clusterização Semântica (TF-IDF + KMeans)
        if len(df) >= 6:
            try:
                clusterizer = CVEClusterizer(n_clusters=6)
                df = clusterizer.fit_predict(df)
                clusterizer.save(MODEL_FILE)
            except Exception as e_cluster:
                print(f"[!] [ML Engine] Aviso no clustering: {e_cluster}. Usando labels genéricos.")
                df["cluster_id"] = 0
                df["cluster_label"] = "Geral / Não Clusterizado"
        else:
            df["cluster_id"] = 0
            df["cluster_label"] = "Geral / Não Clusterizado"

        # 3. Detecção de Exploit Chains com NetworkX
        detector = ExploitChainDetector()
        detector.construir_grafo(df)
        chains = detector.detectar_chains(max_chains=50)

        # 4. Construção dos Writeup Blueprints
        writeups = WriteupBuilder.construir_relatorio_completo(chains)
        print(f"[+] [ML Engine] Concluído: {len(writeups)} Writeup Blueprints de cadeias de ataque gerados com sucesso.\n")

        vulnerabilidades_enriquecidas = df.to_dict("records")
        return vulnerabilidades_enriquecidas, writeups

    except Exception as e_ml:
        print(f"[-] [ML Engine - AVISO] Falha ao processar motor de ML: {e_ml}. Prosseguindo sem ML.")
        return vulnerabilidades_limpas, []