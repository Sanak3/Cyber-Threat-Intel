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

    def construir_grafo(self, df_vulnerabilidades: pd.DataFrame, max_arestas_por_no: int = 6) -> nx.DiGraph:
        """
        Adiciona as CVEs como nós e cria arestas direcionadas para transições de ataque válidas
        no mesmo ecossistema tecnológico e produto/CPE, evitando explosão combinatória O(N^2).
        """
        self.graph.clear()

        # 1. Adicionar nós com metadados estruturados
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
                tecnologia=row.get("tecnologia", "Desconhecido / Geral"),
                cpe_product=row.get("cpe_product") or "",
                cpe_vendor=row.get("cpe_vendor") or ""
            )

        # 2. Agrupar por tecnologia para criar as arestas de transição
        tech_groups = df_vulnerabilidades[
            (df_vulnerabilidades["tecnologia"] != "Desconhecido / Geral") &
            (df_vulnerabilidades["primitiva"] != AttackPrimitive.GENERIC_VULN)
        ].groupby("tecnologia")

        total_arestas = 0
        for tech, group in tech_groups:
            cves = group.to_dict("records")
            # Ordena por severidade decrescente para priorizar conexões com as ameaças mais perigosas
            cves.sort(key=lambda x: float(x.get("nota_cvss", 0.0)), reverse=True)

            por_primitiva: Dict[str, List[Dict[str, Any]]] = {}
            for cve in cves:
                prim = cve.get("primitiva")
                por_primitiva.setdefault(prim, []).append(cve)

            for (prim_origem, prim_destino), desc_transicao in self.TRANSIÇÕES_VALIDAS.items():
                origens = por_primitiva.get(prim_origem, [])
                destinos = por_primitiva.get(prim_destino, [])
                if not origens or not destinos:
                    continue

                for cve_origem in origens:
                    arestas_criadas = 0
                    prod_origem = cve_origem.get("cpe_product")

                    for cve_destino in destinos:
                        if cve_origem["id_cve"] == cve_destino["id_cve"]:
                            continue

                        # Se ambos tiverem CPE de produto definido e forem distintos, evita transição espúria
                        prod_destino = cve_destino.get("cpe_product")
                        if prod_origem and prod_destino and prod_origem != prod_destino:
                            continue

                        self.graph.add_edge(
                            cve_origem["id_cve"],
                            cve_destino["id_cve"],
                            tipo="CHAIN_LINK",
                            tecnologia=tech,
                            descricao_transicao=desc_transicao
                        )
                        total_arestas += 1
                        arestas_criadas += 1
                        if arestas_criadas >= max_arestas_por_no:
                            break

        print(f"[+] [ML Chain Detector] Grafo montado: {self.graph.number_of_nodes():,} nós (CVEs) e {total_arestas:,} arestas de transição (Otimizado por CPE/Degree Bounding).")
        return self.graph

    def detectar_chains(self, max_chains: int = 50, max_caminho: int = 4) -> List[Dict[str, Any]]:
        """
        Descobre caminhos direcionados de ataque no grafo (chains de 2 a 4 elos).
        Consome o gerador nx.all_simple_paths sob demanda (sem list()) e balanceia
        a descoberta entre múltiplos nós de entrada e ecossistemas tecnológicos.
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

        # Balanceamento: calcula teto de cadeias por ecossistema tecnológico
        tecnologias_ativas = list(set(
            attr.get("tecnologia")
            for _, attr in self.graph.nodes(data=True)
            if attr.get("tecnologia") and attr.get("tecnologia") != "Desconhecido / Geral"
        ))
        max_por_tech = max(4, max_chains // max(1, len(tecnologias_ativas)))
        chains_por_tech: Dict[str, int] = {t: 0 for t in tecnologias_ativas}

        for origem in nos_origem:
            tech_origem = self.graph.nodes[origem].get("tecnologia")
            if chains_por_tech.get(tech_origem, 0) >= max_por_tech:
                continue

            chains_desta_origem = 0

            for destino in nos_destino:
                if origem == destino:
                    continue

                if self.graph.nodes[destino].get("tecnologia") != tech_origem:
                    continue

                if nx.has_path(self.graph, origem, destino):
                    # Itera o gerador de caminhos sob demanda evitando estouro de memória
                    for caminho in nx.all_simple_paths(self.graph, origem, destino, cutoff=max_caminho):
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

                        # Se termina em RCE ou Root, a severidade da cadeia é CRITICAL
                        primitiva_final = cve_detalhes[-1]["primitiva"]
                        if primitiva_final in [AttackPrimitive.INJECTION_RCE, AttackPrimitive.PRIV_ESC] and score_combinado >= 7.5:
                            severidade_chain = "CRITICAL"
                        else:
                            severidade_chain = "HIGH"

                        transicoes = []
                        for idx in range(len(caminho) - 1):
                            aresta_data = self.graph.get_edge_data(caminho[idx], caminho[idx + 1]) or {}
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

                        chains_por_tech[tech_origem] = chains_por_tech.get(tech_origem, 0) + 1
                        chains_desta_origem += 1

                        if chains_desta_origem >= 3 or chains_por_tech.get(tech_origem, 0) >= max_por_tech or len(chains_encontradas) >= max_chains:
                            break

                if chains_por_tech.get(tech_origem, 0) >= max_por_tech or len(chains_encontradas) >= max_chains:
                    break

            if len(chains_encontradas) >= max_chains:
                break

        print(f"[+] [ML Chain Detector] Detectadas {len(chains_encontradas)} cadeias de ataque ativas e diversificadas entre ecossistemas.")
        return chains_encontradas
