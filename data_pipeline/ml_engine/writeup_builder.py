from typing import List, Dict, Any
from .primitives import obter_mitre_attack


class WriteupBuilder:
    """
    Construtor de Writeups e Relatórios de Inteligência para Exploit Chains.
    Transforma as cadeias detectadas em especificações técnicas detalhadas
    (Blueprints de Ataque) dinâmicas por primitiva, CWE e status CISA KEV.
    """

    DESCRICAO_ENTRADA = {
        "RECON_INFO_LEAK": "exfiltração de artefatos sensíveis, credenciais ou mapeamento interno",
        "AUTH_BYPASS": "contorno direto de mecanismos de autenticação e controle de acesso",
        "INJECTION_RCE": "execução inicial de instruções arbitrárias em serviço exposto",
    }

    DESCRICAO_IMPACTO_FINAL = {
        "INJECTION_RCE": "execução remota de código arbitrário (RCE) no servidor alvo",
        "PRIV_ESC": "escalação completa de privilégios locais para Root/SYSTEM no host hospedeiro",
        "AUTH_BYPASS": "tomada de controle administrativo sem credenciais válidas",
    }

    @staticmethod
    def _gerar_titulo(tecnologia: str, severidade: str, elos_count: int, primeira_primitiva: str, ultima_primitiva: str, tem_kev: bool) -> str:
        if ultima_primitiva == "PRIV_ESC":
            if primeira_primitiva == "RECON_INFO_LEAK":
                objetivo = "Vazamento de Dados até Escalação Root/SYSTEM"
            else:
                objetivo = "Escalação Total para Privilégios Root/SYSTEM"
        elif ultima_primitiva == "INJECTION_RCE":
            if primeira_primitiva == "AUTH_BYPASS":
                objetivo = "Bypass de Autenticação até Execução Remota de Código (RCE)"
            elif primeira_primitiva == "RECON_INFO_LEAK":
                objetivo = "Exposição de Artefatos até Execução Remota de Código (RCE)"
            else:
                objetivo = "Execução Remota de Código (RCE) Encadeada"
        else:
            objetivo = "Comprometimento de Perímetro e Integridade"

        tag_kev = " [CISA KEV]" if tem_kev else ""
        return f"[{severidade}]{tag_kev} Cadeia em {tecnologia}: {objetivo} ({elos_count} Elos)"

    @classmethod
    def _gerar_resumo_executivo(cls, chain: Dict[str, Any]) -> str:
        tecnologia = chain.get("tecnologia", "Ecossistema")
        cves = chain.get("cves", [])
        cve_detalhes = chain.get("cve_detalhes", [])
        cves_str = " ➔ ".join(cves)
        score = chain.get("score_combinado", 9.5)
        kev_count = int(chain.get("kev_count", 0))

        prim_inicial = cve_detalhes[0].get("primitiva", "RECON_INFO_LEAK") if cve_detalhes else "RECON_INFO_LEAK"
        prim_final = cve_detalhes[-1].get("primitiva", "INJECTION_RCE") if cve_detalhes else "INJECTION_RCE"

        vetor_entrada = cls.DESCRICAO_ENTRADA.get(prim_inicial, "exploração inicial de perímetro")
        objetivo_final = cls.DESCRICAO_IMPACTO_FINAL.get(prim_final, "comprometimento crítico do ativo")

        alerta_kev = (
            f" ALERTA SOC: {kev_count} elo(s) desta cadeia consta(m) no catálogo CISA KEV com exploração ativa confirmada in-the-wild."
            if kev_count > 0
            else ""
        )

        return (
            f"Correlação tática identificada no ecossistema {tecnologia} encadeando {cves_str}. "
            f"O vetor inicia com {vetor_entrada} e progride por pivoting até alcançar {objetivo_final} "
            f"(Score Composto: {score}/10.0).{alerta_kev}"
        )

    @staticmethod
    def _gerar_passos(chain: Dict[str, Any]) -> List[Dict[str, Any]]:
        cve_detalhes = chain.get("cve_detalhes", [])
        transicoes = chain.get("transicoes", [])
        passos = []

        for i, cve in enumerate(cve_detalhes):
            numero_passo = i + 1
            cve_id = cve.get("cve_id")
            primitiva = cve.get("primitiva")
            nota = float(cve.get("nota_cvss") or 0.0)
            descricao = cve.get("descricao", "")
            cwe = cve.get("cwe") or "NVD-CWE-noinfo"
            cisa_kev = bool(cve.get("cisa_kev", False))
            epss_score = round(float(cve.get("epss_score") or 0.0), 5)
            mitre_attack = obter_mitre_attack(primitiva, cwe)

            if i == 0:
                acao = f"Acesso Inicial / Exploração de Perímetro via {cve_id} ({primitiva})."
                detalhe_tecnico = f"O atacante explora o vetor de entrada para estabelecer posição inicial: {descricao}"
            else:
                transicao_info = (
                    transicoes[i - 1].get("motivo", "Aproveitamento do estado anterior")
                    if i - 1 < len(transicoes)
                    else "Aproveitamento do estado anterior"
                )
                acao = f"Pivoting / Escalação Tática via {cve_id} ({primitiva})."
                detalhe_tecnico = f"{transicao_info}. Com a vantagem obtida no passo anterior, aciona o próximo elo: {descricao}"

            passos.append({
                "passo": numero_passo,
                "cve_id": cve_id,
                "primitiva": primitiva,
                "nota_cvss": nota,
                "cwe": cwe,
                "cisa_kev": cisa_kev,
                "epss_score": epss_score,
                "mitre_attack": mitre_attack,
                "acao": acao,
                "detalhe": detalhe_tecnico
            })

        return passos

    @staticmethod
    def _gerar_impacto(cve_detalhes: List[Dict[str, Any]]) -> str:
        primitivas = {c.get("primitiva") for c in cve_detalhes}
        ultima_primitiva = cve_detalhes[-1].get("primitiva") if cve_detalhes else "INJECTION_RCE"

        if ultima_primitiva == "PRIV_ESC":
            if "INJECTION_RCE" in primitivas:
                return (
                    "Comprometimento completo Remoto-para-Root (Full System Takeover): o invasor obtém execução remota "
                    "seguida de escalação para privilégios máximos de kernel/SO, podendo desativar agentes EDR, extrair "
                    "segredos de memória e movimentar-se lateralmente na rede interna."
                )
            return (
                "Comprometimento irrestrito do host hospedeiro. O atacante assume controle total sobre processos, "
                "sistema de arquivos e credenciais administrativas (Root/SYSTEM)."
            )

        if ultima_primitiva == "INJECTION_RCE":
            return (
                "Execução remota de código arbitrário no contexto do serviço vulnerável sem necessidade de credenciais prévias, "
                "viabilizando abertura de reverse shell, exfiltração de banco de dados e implante persistente."
            )

        return "Violação severa de confidencialidade e integridade com exposição não autorizada de ativos críticos."

    @staticmethod
    def _gerar_mitigacoes(chain: Dict[str, Any]) -> List[str]:
        cves = chain.get("cves", [])
        cve_detalhes = chain.get("cve_detalhes", [])
        primitivas = {c.get("primitiva") for c in cve_detalhes}
        kev_cves = [c.get("cve_id") for c in cve_detalhes if c.get("cisa_kev")]

        mitigacoes = []
        if kev_cves:
            mitigacoes.append(
                f"PRIORIDADE MÁXIMA (CISA KEV): Aplicar correções emergenciais imediatas para {', '.join(kev_cves)} "
                f"(exploração ativa confirmada) e demais elos ({', '.join(cves)})."
            )
        else:
            mitigacoes.append(
                f"Aplicar patches oficiais do fabricante para interromper os elos da cadeia: {', '.join(cves)}."
            )

        if "RECON_INFO_LEAK" in primitivas:
            mitigacoes.append(
                "Bloquear leitura arbitrária de arquivos/SSRF restringindo permissões de diretórios sensíveis, "
                "desativando endpoints de diagnóstico expostos e filtrando tráfego de saída (egress filtering)."
            )

        if "AUTH_BYPASS" in primitivas:
            mitigacoes.append(
                "Isolar interfaces administrativas da internet pública via VPN/ZTNA, exigir MFA resistente a phishing "
                "e auditar logs de autenticação em busca de sessões ou contas criadas sem autorização."
            )

        if "INJECTION_RCE" in primitivas:
            mitigacoes.append(
                "Aplicar virtual patching (regras de WAF/IPS contra payloads de injeção/deserialização) e confinar o "
                "serviço em conta não privilegiada com filesystem somente leitura."
            )

        if "PRIV_ESC" in primitivas:
            mitigacoes.append(
                "Endurecer o host/kernel (remover binários SUID desnecessários, restringir namespaces não privilegiados) "
                "e ativar detecção comportamental no EDR para elevação anômala de tokens/UID 0."
            )

        return mitigacoes

    @classmethod
    def construir_writeup(cls, chain: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gera o documento técnico consolidado do writeup a partir de uma cadeia detectada.
        """
        cves = chain.get("cves", [])
        cve_detalhes = chain.get("cve_detalhes", [])
        primeira_primitiva = cve_detalhes[0].get("primitiva") if cve_detalhes else "RECON_INFO_LEAK"
        ultima_primitiva = cve_detalhes[-1].get("primitiva") if cve_detalhes else "INJECTION_RCE"
        tecnologia = chain.get("tecnologia", "Geral")
        severidade = chain.get("severidade_chain", "CRITICAL")
        elos_count = chain.get("elos_count", len(cves))
        kev_count = int(chain.get("kev_count", sum(1 for c in cve_detalhes if c.get("cisa_kev"))))
        tem_kev = bool(chain.get("tem_kev", kev_count > 0))

        titulo = cls._gerar_titulo(tecnologia, severidade, elos_count, primeira_primitiva, ultima_primitiva, tem_kev)
        resumo = cls._gerar_resumo_executivo(chain)
        passos = cls._gerar_passos(chain)
        impacto = cls._gerar_impacto(cve_detalhes)
        mitigacoes = cls._gerar_mitigacoes(chain)

        max_epss = round(
            float(chain.get("max_epss") or max((float(c.get("epss_score") or 0.0) for c in cve_detalhes), default=0.0)),
            5
        )
        taticas_mitre = list(dict.fromkeys(
            f"{p['mitre_attack']['tactic_id']} ({p['mitre_attack']['technique_id']})"
            for p in passos
            if p.get("mitre_attack")
        ))

        return {
            "chain_id": chain.get("chain_id"),
            "titulo": titulo,
            "tecnologia": tecnologia,
            "severidade": severidade,
            "score_cvss": chain.get("score_combinado"),
            "max_epss": max_epss,
            "elos_count": elos_count,
            "kev_count": kev_count,
            "tem_kev": tem_kev,
            "cves": cves,
            "taticas_mitre": taticas_mitre,
            "resumo_executivo": resumo,
            "passos_ataque": passos,
            "impacto_tecnico": impacto,
            "mitigacoes_recomendadas": mitigacoes
        }

    @classmethod
    def construir_relatorio_completo(cls, chains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Processa uma lista de chains e retorna a coleção de writeups prontos.
        """
        return [cls.construir_writeup(c) for c in chains]
