from typing import List, Dict, Any


class WriteupBuilder:
    """
    Construtor de Writeups e Relatórios de Inteligência para Exploit Chains.
    Transforma as cadeias detectadas em especificações técnicas detalhadas
    (Blueprints de Ataque) para exibição no dashboard e consumo pelo time de SOC.
    """

    @staticmethod
    def _gerar_titulo(tecnologia: str, severidade: str, elos_count: int, ultima_primitiva: str) -> str:
        if ultima_primitiva == "PRIV_ESC":
            objetivo = "Escalação Total para Privilégios Root/SYSTEM"
        elif ultima_primitiva == "INJECTION_RCE":
            objetivo = "Execução Remota de Código (RCE) Não Autenticado"
        else:
            objetivo = "Comprometimento de Perímetro e Integridade"

        return f"[{severidade}] Cadeia de Ataque em {tecnologia}: {objetivo} ({elos_count} Elos)"

    @staticmethod
    def _gerar_resumo_executivo(chain: Dict[str, Any]) -> str:
        tecnologia = chain.get("tecnologia", "Ecossistema")
        cves = chain.get("cves", [])
        cves_str = ", ".join(cves)
        score = chain.get("score_combinado", 10.0)

        return (
            f"Foi identificada uma correlação de alto risco envolvendo o ecossistema {tecnologia}. "
            f"Um agente malicioso pode encadear as vulnerabilidades {cves_str} "
            f"para ultrapassar as barreiras de autenticação e alcançar a execução arbitrária de instruções no servidor. "
            f"O score de risco composto desta cadeia é avaliado em {score}/10.0."
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
            nota = cve.get("nota_cvss")
            descricao = cve.get("descricao")

            if i == 0:
                acao = f"Acesso Inicial / Exploração de Perímetro utilizando {cve_id} ({primitiva})."
                detalhe_tecnico = f"O atacante explora a falha no componente para obter vantagens de estágio inicial: {descricao}"
            else:
                transicao_info = transicoes[i - 1].get("motivo", "Aproveitamento do estado anterior.") if i - 1 < len(transicoes) else ""
                acao = f"Pivoting / Transição para {cve_id} ({primitiva})."
                detalhe_tecnico = f"{transicao_info}. Com o acesso anterior, o atacante interage com o novo vetor: {descricao}"

            passos.append({
                "passo": numero_passo,
                "cve_id": cve_id,
                "primitiva": primitiva,
                "nota_cvss": nota,
                "acao": acao,
                "detalhe": detalhe_tecnico
            })

        return passos

    @staticmethod
    def _gerar_impacto(ultima_primitiva: str) -> str:
        if ultima_primitiva == "PRIV_ESC":
            return "Comprometimento irrestrito do host. O atacante obtém controle total sobre processos, arquivos de sistema e credenciais administrativas."
        if ultima_primitiva == "INJECTION_RCE":
            return "Execução de comandos arbitrários no contexto do serviço vulnerável. Possibilidade de abertura de reverse shell, extração de banco de dados e persistência lateral."
        return "Violação de confidencialidade e integridade da aplicação com exposição de dados restritos."

    @staticmethod
    def _gerar_mitigacoes(cves: List[str]) -> List[str]:
        return [
            f"Aplicar patches de segurança emergenciais para os identificadores: {', '.join(cves)}.",
            "Implementar segmentação estrita de rede e isolamento do componente afetado.",
            "Configurar regras de WAF/IPS para bloquear payloads direcionados aos endpoints correlacionados.",
            "Aplicar o princípio do menor privilégio para impedir a propagação em caso de quebra de perímetro."
        ]

    @classmethod
    def construir_writeup(cls, chain: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gera o documento técnico consolidado do writeup a partir de uma cadeia detectada.
        """
        cves = chain.get("cves", [])
        cve_detalhes = chain.get("cve_detalhes", [])
        ultima_primitiva = cve_detalhes[-1].get("primitiva") if cve_detalhes else "INJECTION_RCE"
        tecnologia = chain.get("tecnologia", "Geral")
        severidade = chain.get("severidade_chain", "CRITICAL")
        elos_count = chain.get("elos_count", len(cves))

        titulo = cls._gerar_titulo(tecnologia, severidade, elos_count, ultima_primitiva)
        resumo = cls._gerar_resumo_executivo(chain)
        passos = cls._gerar_passos(chain)
        impacto = cls._gerar_impacto(ultima_primitiva)
        mitigacoes = cls._gerar_mitigacoes(cves)

        return {
            "chain_id": chain.get("chain_id"),
            "titulo": titulo,
            "tecnologia": tecnologia,
            "severidade": severidade,
            "score_cvss": chain.get("score_combinado"),
            "cves": cves,
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
