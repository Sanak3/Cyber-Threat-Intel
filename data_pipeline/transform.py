import numpy as np

def transformar_dados(dados_brutos):
    print("[+] Iniciando transformação e análise com NumPy...")
    vulnerabilidades_limpas = []
    notas_cvss = []

    for item in dados_brutos.get("vulnerabilities", []):
        cve = item.get("cve", {})
        id_cve = cve.get("id")

        descricoes = cve.get("descriptions", [])
        descricao = next((d.get("value") for d in descricoes if d.get("lang") == "en"), "Sem descrição")

        metrics = cve.get("metrics", {})
        # a nvd usa cvssmetricv31 ou cvssmetricv30 dependendo da cve
        cvss_data = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})

        if not cvss_data:
            cvss_data = metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})

        nota = cvss_data.get("baseScore", 0.0)
        severidade = cvss_data.get("baseSeverity", "UNKNOWN")

        vulnerabilidades_limpas.append({
            "id_cve": id_cve,
            "descricao": descricao,
            "nota_cvss": nota,
            "severidade": severidade
        })

        if nota > 0.0:
            notas_cvss.append(nota)

    # analise matematica de risco com numpy
    array_notas = np.array(notas_cvss)

    if len(array_notas) > 0:
        media_risco = np.mean(array_notas)
        risco_maximo = np.max(array_notas)
        ameacas_criticas = np.sum(array_notas >= 7.0)

        print("-" * 40)
        print("  INTELIGÊNCIA DE AMEAÇAS (NumPy Engine)  ")
        print("-" * 40)
        print(f"[*] Média de Risco Global: {media_risco:.2f}")
        print(f"[*] Pior Risco Detectado:  {risco_maximo}")
        print(f"[*] Ameaças Altas/Críticas (CVSS >= 7): {ameacas_criticas}")
        print("-" * 40 + "\n")

    return vulnerabilidades_limpas