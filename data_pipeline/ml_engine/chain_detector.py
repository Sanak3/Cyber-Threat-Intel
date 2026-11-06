from typing import List, Dict, Any
import pandas as pd
import networkx as nx
from .primitives import AttackPrimitive


class ExploitChainDetector:
    """
    Detector de Cadeias de Ataque (Exploit Chains) utilizando Grafos Direcionados (NetworkX).
    Identifica combinações viáveis de vulnerabilidades que, quando encadeadas,
    permitem a um atacante evoluir de um acesso inicial até o comprometimento total do sistema.
    """

    # Transições de ataque taticamente válidas na Cyber Kill Chain
    TRANSIÇÕES_VALIDAS = {
        (AttackPrimitive.RECON_INFO_LEAK, AttackPrimitive.AUTH_BYPASS): "Leitura/Vazamento de credenciais facilita Bypass de Autenticação",
        (AttackPrimitive.RECON_INFO_LEAK, AttackPrimitive.INJECTION_RCE): "Vazamento de configurações/arquivos viabiliza Execução Remota de Código",
        (AttackPrimitive.AUTH_BYPASS, AttackPrimitive.INJECTION_RCE): "Bypass de login expõe endpoints administrativos a Injeção/RCE",
        (AttackPrimitive.INJECTION_RCE, AttackPrimitive.PRIV_ESC): "Acesso inicial com shell limitado viabiliza Escalação Local de Privilégio para Root/SYSTEM",
        (AttackPrimitive.AUTH_BYPASS, AttackPrimitive.PRIV_ESC): "Acesso autenticado de baixa permissão combinado com Escalação de Privilégio",
    }

    # Subprodutos de sistema operacional / kernel que podem ser alvo de Escalação de Privilégio (PRIV_ESC)
    # após comprometimento de uma aplicação hospedada no mesmo ecossistema
    HOST_OS_SUBPRODUCTS = {
        "windows",
        "windows_server",
        "windows_10",
        "windows_11",
        "linux",
        "linux_kernel",
        "ubuntu_linux",
        "debian_linux",
        "enterprise_linux",
        "macos",
        "mac_os_x",
        "iphone_os",
        "ios",
        "ipados",
        "android",
        "esxi",
    }

    def __init__(self):
        self.graph = nx.DiGraph()

    @classmethod
    def _produtos_compativeis(cls, cve_origem: Dict[str, Any], cve_destino: Dict[str, Any], prim_destino: str) -> bool:
        """
        Verifica compatibilidade de produto/subproduto entre dois elos:
        - Se ambos definem subproduto/CPE e forem iguais -> compatíveis.
        - Se forem diferentes, permite apenas transição para PRIV_ESC no SO/Kernel hospedeiro
          (ex.: Exchange/IIS RCE -> Windows Kernel PRIV_ESC, Safari -> macOS, Chrome -> Android),
          bloqueando falsos positivos entre softwares distintos (ex.: Jenkins -> Kubernetes, Kafka -> Tomcat).
        """
        prod_origem = (cve_origem.get("subproduto") or cve_origem.get("cpe_product") or "").strip().lower()
        prod_destino = (cve_destino.get("subproduto") or cve_destino.get("cpe_product") or "").strip().lower()

        if not prod_origem or not prod_destino:
            return True

        if prod_origem == prod_destino:
            return True

        if prim_destino == AttackPrimitive.PRIV_ESC and prod_destino in cls.HOST_OS_SUBPRODUCTS:
            return True

        return False

    @staticmethod
    def _calcular_score_composto(cve_detalhes: List[Dict[str, Any]], kev_count: int) -> float:
        """
        Calcula score composto sem saturação artificial:
        combina maior nota (65%), média dos elos (35%), sinergia do encadeamento
        e bonificação tática para vulnerabilidades confirmadas no catálogo CISA KEV.
        """
        notas = [float(c.get("nota_cvss", 0.0)) for c in cve_detalhes if float(c.get("nota_cvss", 0.0)) > 0]
        if not notas:
            base = 7.0
        else:
            max_nota = max(notas)
            media_notas = sum(notas) / len(notas)
            base = (0.65 * max_nota) + (0.35 * media_notas)

        elos_extras = max(0, min(len(cve_detalhes) - 2, 2))
        bonus_sinergia = 0.25 + (0.20 * elos_extras)
        bonus_kev = min(0.50, 0.30 * kev_count)

        return round(min(10.0, base + bonus_sinergia + bonus_kev), 1)

    def construir_grafo(self, df_vulnerabilidades: pd.DataFrame, max_arestas_por_no: int = 6) -> nx.DiGraph:
        """
        Adiciona as CVEs como nós e cria arestas direcionadas para transições de ataque válidas
        no mesmo ecossistema tecnológico e produto/subproduto compatível, evitando explosão O(N^2).
        """
        self.graph.clear()
        if df_vulnerabilidades is None or df_vulnerabilidades.empty:
            return self.graph

        # 1. Adicionar nós com metadados estruturados (incluindo CISA KEV, CWE e subproduto)
        for _, row in df_vulnerabilidades.iterrows():
            cve_id = row.get("id_cve")
            if not cve_id:
                continue

            cpe_prod = str(row.get("cpe_product") or "").strip().lower()
            subprod = str(row.get("subproduto") or cpe_prod).strip().lower()

            self.graph.add_node(
                cve_id,
                cve_id=cve_id,
                descricao=row.get("descricao", ""),
                nota_cvss=float(row.get("nota_cvss", 0.0)),
                severidade=row.get("severidade", "UNKNOWN"),
                primitiva=row.get("primitiva", AttackPrimitive.GENERIC_VULN),
                estagio=int(row.get("estagio_kill_chain", 0)),
                tecnologia=row.get("tecnologia", "Desconhecido / Geral"),
                cpe_product=cpe_prod,
                cpe_vendor=str(row.get("cpe_vendor") or "").strip().lower(),
                subproduto=subprod,
                cwe=row.get("cwe") or "NVD-CWE-noinfo",
                cisa_kev=bool(row.get("cisa_kev", False)),
                data_publicacao=row.get("data_publicacao"),
            )

        # 2. Agrupar por tecnologia para criar as arestas de transição
        tech_groups = df_vulnerabilidades[
            (df_vulnerabilidades["tecnologia"] != "Desconhecido / Geral") &
            (df_vulnerabilidades["primitiva"] != AttackPrimitive.GENERIC_VULN)
        ].groupby("tecnologia")

        total_arestas = 0
        for tech, group in tech_groups:
            cves = group.to_dict("records")
            # Prioriza CVEs exploradas ativamente (CISA KEV) e de maior severidade CVSS
            cves.sort(
                key=lambda x: (bool(x.get("cisa_kev", False)), float(x.get("nota_cvss", 0.0))),
                reverse=True
            )

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

                    for cve_destino in destinos:
                        if cve_origem["id_cve"] == cve_destino["id_cve"]:
                            continue

                        if not self._produtos_compativeis(cve_origem, cve_destino, prim_destino):
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

        print(f"[+] [ML Chain Detector] Grafo montado: {self.graph.number_of_nodes():,} nós (CVEs) e {total_arestas:,} arestas táticas (CPE/Subproduto + KEV Priority).")
        return self.graph

    def detectar_chains(self, max_chains: int = 50, max_caminho: int = 4) -> List[Dict[str, Any]]:
        """
        Descobre caminhos direcionados de ataque no grafo (chains de 2 a 4 elos).
        Prioriza vulnerabilidades CISA KEV, controla dominância de nós hub (origem e destino)
        para evitar cadeias repetitivas e ordena o ranking final por criticidade real.
        """
        if self.graph.number_of_edges() == 0:
            return []

        chains_candidatas = []

        def chave_prioridade_no(node_id: str):
            attr = self.graph.nodes[node_id]
            return (
                1 if attr.get("cisa_kev") else 0,
                float(attr.get("nota_cvss", 0.0))
            )

        # Nós de entrada (Acesso Inicial: Recon ou Auth Bypass) ordenados por KEV e CVSS
        nos_origem = sorted(
            [
                n for n, attr in self.graph.nodes(data=True)
                if attr.get("primitiva") in [AttackPrimitive.RECON_INFO_LEAK, AttackPrimitive.AUTH_BYPASS]
            ],
            key=chave_prioridade_no,
            reverse=True
        )

        # Nós de término de alto impacto (Execução de Código ou PrivEsc) ordenados por KEV e CVSS
        nos_destino = sorted(
            [
                n for n, attr in self.graph.nodes(data=True)
                if attr.get("primitiva") in [AttackPrimitive.INJECTION_RCE, AttackPrimitive.PRIV_ESC]
            ],
            key=chave_prioridade_no,
            reverse=True
        )

        visitados = set()

        # Balanceamento entre ecossistemas e controle anti-hub em nós de destino
        tecnologias_ativas = list(set(
            attr.get("tecnologia")
            for _, attr in self.graph.nodes(data=True)
            if attr.get("tecnologia") and attr.get("tecnologia") != "Desconhecido / Geral"
        ))
        max_por_tech = max(4, (max_chains + max(1, len(tecnologias_ativas)) - 1) // max(1, len(tecnologias_ativas)) + 1)
        chains_por_tech: Dict[str, int] = {t: 0 for t in tecnologias_ativas}
        uso_destino: Dict[str, int] = {}
        max_uso_destino = 2
        limite_coleta = max(max_chains * 2, 60)

        for origem in nos_origem:
            tech_origem = self.graph.nodes[origem].get("tecnologia")
            if chains_por_tech.get(tech_origem, 0) >= max_por_tech:
                continue

            chains_desta_origem = 0

            for destino in nos_destino:
                if origem == destino:
                    continue

                if uso_destino.get(destino, 0) >= max_uso_destino:
                    continue

                if self.graph.nodes[destino].get("tecnologia") != tech_origem:
                    continue

                if nx.has_path(self.graph, origem, destino):
                    for caminho in nx.all_simple_paths(self.graph, origem, destino, cutoff=max_caminho):
                        if len(caminho) < 2:
                            continue

                        assinatura_chain = "->".join(caminho)
                        if assinatura_chain in visitados:
                            continue
                        visitados.add(assinatura_chain)

                        cve_detalhes = [self.graph.nodes[node_id] for node_id in caminho]
                        tecnologia = cve_detalhes[0]["tecnologia"]
                        kev_count = sum(1 for c in cve_detalhes if c.get("cisa_kev"))
                        tem_kev = kev_count > 0

                        score_combinado = self._calcular_score_composto(cve_detalhes, kev_count)

                        primitiva_final = cve_detalhes[-1]["primitiva"]
                        if (primitiva_final in [AttackPrimitive.INJECTION_RCE, AttackPrimitive.PRIV_ESC] and score_combinado >= 8.5) or tem_kev:
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

                        chains_candidatas.append({
                            "tecnologia": tecnologia,
                            "elos_count": len(caminho),
                            "cves": caminho,
                            "cve_detalhes": cve_detalhes,
                            "transicoes": transicoes,
                            "score_combinado": score_combinado,
                            "severidade_chain": severidade_chain,
                            "kev_count": kev_count,
                            "tem_kev": tem_kev,
                        })

                        chains_por_tech[tech_origem] = chains_por_tech.get(tech_origem, 0) + 1
                        uso_destino[destino] = uso_destino.get(destino, 0) + 1
                        chains_desta_origem += 1

                        if (
                            chains_desta_origem >= 2
                            or uso_destino[destino] >= max_uso_destino
                            or chains_por_tech.get(tech_origem, 0) >= max_por_tech
                            or len(chains_candidatas) >= limite_coleta
                        ):
                            break

                if chains_por_tech.get(tech_origem, 0) >= max_por_tech or len(chains_candidatas) >= limite_coleta:
                    break

            if len(chains_candidatas) >= limite_coleta:
                break

        # Ordena globalmente priorizando cadeias com exploração ativa (CISA KEV), maior score composto e profundidade
        chains_candidatas.sort(
            key=lambda c: (1 if c.get("tem_kev") else 0, c.get("score_combinado", 0.0), c.get("elos_count", 0)),
            reverse=True
        )

        chains_finais = chains_candidatas[:max_chains]
        for idx, chain in enumerate(chains_finais, start=1):
            chain["chain_id"] = f"CHAIN-{idx:04d}"

        print(f"[+] [ML Chain Detector] Detectadas {len(chains_finais)} cadeias de ataque diversificadas e priorizadas por risco/CISA KEV.")
        return chains_finais
