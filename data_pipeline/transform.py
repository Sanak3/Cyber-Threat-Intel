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

    total_extraido = len(dados_brutos.get("vulnerabilities", []))
    total_com_nota = len(array_notas)
    aguardando_analise = total_extraido - total_com_nota

    if len(array_notas) > 0:
        media_risco = np.mean(array_notas)
        risco_maximo = np.max(array_notas)

        criticas = np.sum(array_notas >= 9.0)
        altas = np.sum((array_notas >= 7.0) & (array_notas < 9.0))
        medias = np.sum((array_notas >= 4.0) & (array_notas < 7.0))
        baixas = np.sum((array_notas > 0.0) & (array_notas < 4.0))

        print("-" * 55)
        print("         INTELIGÊNCIA DE AMEAÇAS (NumPy Engine)      ")
        print("-" * 55)
        print(f"[*] Total de CVEs Coletados: {total_extraido}")
        print(f"[*] CVEs Aguardando Análise (NIST): {aguardando_analise}")
        print(f"[*] CVEs Avaliados e Prontos: {total_com_nota}")
        print("-" * 55)
        print(f"[*] Média de Risco Global (Avaliados): {media_risco:.2f}")
        print(f"[*] Pior Risco Detectado:  {risco_maximo}")
        print("[*] Distribuição de Severidade:")
        print(f"    - [CRÍTICO] (9.0 - 10.0): {criticas} ameaças")
        print(f"    - [ALTO]    (7.0 - 8.9):  {altas} ameaças")
        print(f"    - [MÉDIO]   (4.0 - 6.9):  {medias} ameaças")
        print(f"    - [BAIXO]   (0.1 - 3.9):  {baixas} ameaças")
        print("-" * 55 + "\n")

    return vulnerabilidades_limpas