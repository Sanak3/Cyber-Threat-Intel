from typing import List, Dict, Any, Tuple
import pandas as pd
import networkx as nx
from .primitives import AttackPrimitive


class ExploitChainDetector:
    """
    Detector de Cadeias de Ataque (Exploit Chains) utilizando Grafos Direcionados (NetworkX).
    Identifica combinações viáveis de vulnerabilidades que, quando encadeadas,
    permitem a um atacante evoluir de um acesso inicial até o comprometimento total do sistema.
    """

    # Transições de ataque taticamente válidas
    TRANSIÇÕES_VALIDAS = {
        (AttackPrimitive.RECON_INFO_LEAK, AttackPrimitive.AUTH_BYPASS): "Leitura/Vazamento de credenciais facilita Bypass de Autenticação",
        (AttackPrimitive.RECON_INFO_LEAK, AttackPrimitive.INJECTION_RCE): "Vazamento de configurações/arquivos viabiliza Execução Remota de Código",
        (AttackPrimitive.AUTH_BYPASS, AttackPrimitive.INJECTION_RCE): "Bypass de login expõe endpoints administrativos a Injeção/RCE",
        (AttackPrimitive.INJECTION_RCE, AttackPrimitive.PRIV_ESC): "Acesso inicial com shell limitado viabiliza Escalação Local de Privilégio para Root",
        (AttackPrimitive.AUTH_BYPASS, AttackPrimitive.PRIV_ESC): "Acesso de baixa permissão combinado com Escalação de Privilégio",
    }

    def __init__(self):
        self.graph = nx.DiGraph()

    def construir_grafo(self, df_vulnerabilidades: pd.DataFrame) -> nx.DiGraph:
        """
        Adiciona as CVEs como nós e cria arestas direcionadas para transições de ataque válidas
        no mesmo ecossistema tecnológico.
        """
        self.graph.clear()

        # 1. Adicionar nós
        for _, row in df_vulnerabilidades.iterrows():
            cve_id = row.get("id_cve")
            if not cve_id:
                continue

            self.graph.add_node(
                cve_id,
                cve_id=cve_id,
                descricao=row.get("descricao", ""),
                nota_cvss=float(row.get("nota_cvss", 0.0)),
                severidade=row.get("severidade", "UNKNOWN"),
                primitiva=row.get("primitiva", AttackPrimitive.GENERIC_VULN),
                estagio=int(row.get("estagio_kill_chain", 0)),
                tecnologia=row.get("tecnologia", "Desconhecido / Geral")
            )

        # 2. Agrupar por tecnologia para criar as arestas de transição
        # Apenas tecnologias conhecidas são candidatas para chains reais
        tech_groups = df_vulnerabilidades[
            (df_vulnerabilidades["tecnologia"] != "Desconhecido / Geral") &
            (df_vulnerabilidades["primitiva"] != AttackPrimitive.GENERIC_VULN)
        ].groupby("tecnologia")

        total_arestas = 0
        for tech, group in tech_groups:
            cves = group.to_dict("records")
            n = len(cves)

            for i in range(n):
                cve_origem = cves[i]
                prim_origem = cve_origem.get("primitiva")

                for j in range(n):
                    if i == j:
                        continue

                    cve_destino = cves[j]
                    prim_destino = cve_destino.get("primitiva")

                    par_transicao = (prim_origem, prim_destino)
                    if par_transicao in self.TRANSIÇÕES_VALIDAS:
                        descricao_aresta = self.TRANSIÇÕES_VALIDAS[par_transicao]

                        self.graph.add_edge(
                            cve_origem["id_cve"],
                            cve_destino["id_cve"],
                            tipo="CHAIN_LINK",
                            tecnologia=tech,
                            descricao_transicao=descricao_aresta
                        )
                        total_arestas += 1

        print(f"[+] [ML Chain Detector] Grafo montado: {self.graph.number_of_nodes():,} nós (CVEs) e {total_arestas:,} arestas de transição.")
        return self.graph

    def detectar_chains(self, max_chains: int = 50, max_caminho: int = 4) -> List[Dict[str, Any]]:
        """
        Descobre caminhos direcionados de ataque no grafo (chains de 2 a 4 elos).
        Prioriza cadeias que atingem RCE ou Escalação de Privilégios (Root).
        """
        if self.graph.number_of_edges() == 0:
            return []

        chains_encontradas = []

        # Identificar nós de entrada (Acesso Inicial: Recon ou Auth Bypass)
        nos_origem = [
            n for n, attr in self.graph.nodes(data=True)
            if attr.get("primitiva") in [AttackPrimitive.RECON_INFO_LEAK, AttackPrimitive.AUTH_BYPASS]
        ]

        # Identificar nós de término de alto impacto (Execução de Código ou PrivEsc)
        nos_destino = [
            n for n, attr in self.graph.nodes(data=True)
            if attr.get("primitiva") in [AttackPrimitive.INJECTION_RCE, AttackPrimitive.PRIV_ESC]
        ]

        visitados = set()

        for origem in nos_origem:
            for destino in nos_destino:
                if origem == destino:
                    continue

                if nx.has_path(self.graph, origem, destino):
                    # Encontra caminhos simples de até max_caminho nós
                    caminhos = list(nx.all_simple_paths(self.graph, origem, destino, cutoff=max_caminho))

                    for caminho in caminhos:
                        if len(caminho) < 2:
                            continue

                        assinatura_chain = "->".join(caminho)
                        if assinatura_chain in visitados:
                            continue
                        visitados.add(assinatura_chain)

                        # Monta os detalhes da cadeia
                        cve_detalhes = [self.graph.nodes[node_id] for node_id in caminho]
                        tecnologia = cve_detalhes[0]["tecnologia"]

                        # Calcula score composto de risco
                        notas = [c["nota_cvss"] for c in cve_detalhes if c["nota_cvss"] > 0]
                        score_combinado = min(10.0, max(notas) * 1.05) if notas else 7.0

                        # Se termina em RCE ou Root, a severidade da cadeia é sempre CRITICAL ou HIGH
                        primitiva_final = cve_detalhes[-1]["primitiva"]
                        if primitiva_final in [AttackPrimitive.INJECTION_RCE, AttackPrimitive.PRIV_ESC] and score_combinado >= 7.5:
                            severidade_chain = "CRITICAL"
                        else:
                            severidade_chain = "HIGH"

                        transicoes = []
                        for idx in range(len(caminho) - 1):
                            aresta_data = self.graph.get_edge_data(caminho[idx], caminho[idx + 1])
                            transicoes.append({
                                "de": caminho[idx],
                                "para": caminho[idx + 1],
                                "motivo": aresta_data.get("descricao_transicao", "Transição válida")
                            })

                        chains_encontradas.append({
                            "chain_id": f"CHAIN-{len(chains_encontradas) + 1:04d}",
                            "tecnologia": tecnologia,
                            "elos_count": len(caminho),
                            "cves": caminho,
                            "cve_detalhes": cve_detalhes,
                            "transicoes": transicoes,
                            "score_combinado": round(score_combinado, 1),
                            "severidade_chain": severidade_chain
                        })

                        if len(chains_encontradas) >= max_chains:
                            break

                if len(chains_encontradas) >= max_chains:
                    break
            if len(chains_encontradas) >= max_chains:
                break

        print(f"[+] [ML Chain Detector] Detectadas {len(chains_encontradas)} cadeias de ataque ativas.")
        return chains_encontradas
