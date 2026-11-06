import sys
import os
import unittest
from unittest.mock import patch, MagicMock
import pandas as pd

# Adiciona o diretório data_pipeline ao path para importação direta
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data_pipeline")))

from extract import extrair_dados_nist, extrair_scores_epss
from transform import extrair_metricas_cvss, sanitizar_texto, transformar_dados
from ml_engine.primitives import (
    AttackPrimitive,
    extrair_primitiva,
    extrair_tecnologia,
    extrair_subproduto,
    obter_mitre_attack,
    enriquecer_vulnerabilidades
)
from ml_engine.chain_detector import ExploitChainDetector
from ml_engine.clusterizer import CVEClusterizer
from ml_engine.writeup_builder import WriteupBuilder


class TestThreatPipeline(unittest.TestCase):

    def test_extrair_metricas_cvss_v31(self):
        metrics = {
            "cvssMetricV31": [{
                "cvssData": {
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL"
                }
            }]
        }
        score, sev = extrair_metricas_cvss(metrics)
        self.assertEqual(score, 9.8)
        self.assertEqual(sev, "CRITICAL")

    def test_extrair_metricas_cvss_v30_fallback(self):
        metrics = {
            "cvssMetricV30": [{
                "cvssData": {
                    "baseScore": 7.5,
                    "baseSeverity": "HIGH"
                }
            }]
        }
        score, sev = extrair_metricas_cvss(metrics)
        self.assertEqual(score, 7.5)
        self.assertEqual(sev, "HIGH")

    def test_extrair_metricas_cvss_v2_fallback(self):
        metrics = {
            "cvssMetricV2": [{
                "cvssData": {
                    "baseScore": 5.0
                },
                "baseSeverity": "MEDIUM"
            }]
        }
        score, sev = extrair_metricas_cvss(metrics)
        self.assertEqual(score, 5.0)
        self.assertEqual(sev, "MEDIUM")

    def test_extrair_metricas_cvss_v2_promove_critical(self):
        # No CVSS v2 legado, notas 9.0-10.0 vinham como HIGH; devem ser normalizadas para CRITICAL
        metrics = {
            "cvssMetricV2": [{
                "cvssData": {
                    "baseScore": 10.0
                },
                "baseSeverity": "HIGH"
            }]
        }
        score, sev = extrair_metricas_cvss(metrics)
        self.assertEqual(score, 10.0)
        self.assertEqual(sev, "CRITICAL")

    def test_extrair_metricas_cvss_v40_fallback(self):
        metrics = {
            "cvssMetricV40": [{
                "type": "Primary",
                "cvssData": {
                    "baseScore": 9.3,
                    "baseSeverity": "CRITICAL"
                }
            }]
        }
        score, sev = extrair_metricas_cvss(metrics)
        self.assertEqual(score, 9.3)
        self.assertEqual(sev, "CRITICAL")

    def test_extrair_metricas_cvss_empty(self):
        score, sev = extrair_metricas_cvss({})
        self.assertEqual(score, 0.0)
        self.assertEqual(sev, "UNKNOWN")

    def test_sanitizar_texto(self):
        self.assertEqual(sanitizar_texto("Texto\x00 com byte nulo"), "Texto com byte nulo")
        self.assertEqual(sanitizar_texto(None), "Sem descrição disponível.")

    def test_transformar_dados_descarta_rejected(self):
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-0001",
                        "vulnStatus": "Rejected",
                        "descriptions": [{"lang": "en", "value": "** REJECT ** DO NOT USE THIS CANDIDATE NUMBER."}],
                        "metrics": {}
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2026-0002",
                        "vulnStatus": "Analyzed",
                        "published": "2026-05-01T10:00:00.000",
                        "lastModified": "2026-05-02T12:00:00.000",
                        "descriptions": [{"lang": "en", "value": "SQL injection in Apache Tomcat"}],
                        "metrics": {
                            "cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
                        },
                        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-89"}]}],
                        "cisaExploitAdd": "2026-05-02"
                    }
                }
            ]
        }
        res = transformar_dados(payload)
        vulnerabilidades = res[0] if isinstance(res, tuple) else res
        self.assertEqual(len(vulnerabilidades), 1)
        self.assertEqual(vulnerabilidades[0]["id_cve"], "CVE-2026-0002")
        self.assertTrue(vulnerabilidades[0]["cisa_kev"])
        self.assertEqual(vulnerabilidades[0]["cwe"], "CWE-89")

    def test_extrair_primitiva_com_cwe(self):
        # CWE-89 -> SQL Injection (INJECTION_RCE)
        res_sqli = extrair_primitiva("Vulnerability in database", cwe="CWE-89")
        self.assertEqual(res_sqli["primitiva"], AttackPrimitive.INJECTION_RCE)

        # CWE-287 -> Auth Bypass
        res_auth = extrair_primitiva("Login issue", cwe="CWE-287")
        self.assertEqual(res_auth["primitiva"], AttackPrimitive.AUTH_BYPASS)

        # CWE-269 -> Priv Esc
        res_priv = extrair_primitiva("Permission issue", cwe="CWE-269")
        self.assertEqual(res_priv["primitiva"], AttackPrimitive.PRIV_ESC)

    def test_extrair_primitiva_regex_fallback(self):
        res = extrair_primitiva("An attacker can achieve remote code execution via buffer overflow")
        self.assertEqual(res["primitiva"], AttackPrimitive.INJECTION_RCE)

    def test_extrair_tecnologia(self):
        # Resolução por CPE
        tech_cpe = extrair_tecnologia("Generic issue", cpe_vendor="microsoft")
        self.assertEqual(tech_cpe, "Microsoft / Windows")

        tech_cpe_linux = extrair_tecnologia("Generic issue", cpe_vendor="canonical")
        self.assertEqual(tech_cpe_linux, "Linux / Kernel")

        # Resolução por Regex na descrição
        tech_regex = extrair_tecnologia("Vulnerability in Apache Tomcat application server")
        self.assertEqual(tech_regex, "Apache Foundation")

    def test_exploit_chain_detector(self):
        sample_data = [
            {
                "id_cve": "CVE-2024-0001",
                "descricao": "Information disclosure allows reading configuration files",
                "nota_cvss": 5.3,
                "severidade": "MEDIUM",
                "primitiva": AttackPrimitive.RECON_INFO_LEAK,
                "estagio_kill_chain": 1,
                "tecnologia": "Apache Foundation",
                "cpe_product": "http_server"
            },
            {
                "id_cve": "CVE-2024-0002",
                "descricao": "Authentication bypass allows admin access",
                "nota_cvss": 8.8,
                "severidade": "HIGH",
                "primitiva": AttackPrimitive.AUTH_BYPASS,
                "estagio_kill_chain": 2,
                "tecnologia": "Apache Foundation",
                "cpe_product": "http_server"
            },
            {
                "id_cve": "CVE-2024-0003",
                "descricao": "Remote code execution through file upload",
                "nota_cvss": 9.8,
                "severidade": "CRITICAL",
                "primitiva": AttackPrimitive.INJECTION_RCE,
                "estagio_kill_chain": 3,
                "tecnologia": "Apache Foundation",
                "cpe_product": "http_server"
            }
        ]
        df = pd.DataFrame(sample_data)
        detector = ExploitChainDetector()
        grafo = detector.construir_grafo(df)
        self.assertEqual(grafo.number_of_nodes(), 3)
        self.assertGreaterEqual(grafo.number_of_edges(), 2)

        chains = detector.detectar_chains(max_chains=10)
        self.assertGreater(len(chains), 0)
        self.assertEqual(chains[0]["tecnologia"], "Apache Foundation")
        self.assertIn(chains[0]["severidade_chain"], ["HIGH", "CRITICAL"])

    def test_clusterizer_precedencia_rce(self):
        clusterizer = CVEClusterizer(n_clusters=6)
        nome_rce = clusterizer._gerar_nome_cluster(["arbitrary", "code", "execution", "remote", "attacker"])
        self.assertEqual(nome_rce, "Remote Code Execution (RCE)")
        nome_traversal = clusterizer._gerar_nome_cluster(["directory", "traversal", "path", "read", "files"])
        self.assertEqual(nome_traversal, "Path Traversal & Arbitrary File Access")

    @patch("extract.time.sleep", return_value=None)
    @patch("extract.requests.Session")
    def test_extrair_dados_nist_encerra_quando_catalogo_esgota(self, mock_session_cls, _mock_sleep):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {
            "totalResults": 2,
            "vulnerabilities": [
                {"cve": {"id": "CVE-2026-1001"}},
                {"cve": {"id": "CVE-2026-1002"}}
            ]
        }
        mock_session.get.return_value = mock_resp

        resultado = extrair_dados_nist(total_desejado=100, max_por_pagina=50, janela_dias=7)
        self.assertIsNotNone(resultado)
        self.assertEqual(len(resultado["vulnerabilities"]), 2)
        self.assertEqual(mock_session.get.call_count, 1)

    @patch("extract.time.sleep", return_value=None)
    @patch("extract.requests.Session")
    def test_extrair_dados_nist_mescla_catalogo_kev_sem_duplicar(self, mock_session_cls, _mock_sleep):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        resp_discovery = MagicMock(status_code=200)
        resp_discovery.raise_for_status.return_value = None
        resp_discovery.json.return_value = {"totalResults": 5000}

        resp_main = MagicMock(status_code=200)
        resp_main.raise_for_status.return_value = None
        resp_main.json.return_value = {
            "totalResults": 5000,
            "vulnerabilities": [
                {"cve": {"id": "CVE-2026-3001"}},
                {"cve": {"id": "CVE-2026-3002", "cisaExploitAdd": "2026-05-01"}}
            ]
        }

        resp_kev = MagicMock(status_code=200)
        resp_kev.raise_for_status.return_value = None
        resp_kev.json.return_value = {
            "totalResults": 2,
            "vulnerabilities": [
                {"cve": {"id": "CVE-2026-3002", "cisaExploitAdd": "2026-05-01"}},
                {"cve": {"id": "CVE-2021-44228", "cisaExploitAdd": "2021-12-10"}}
            ]
        }

        mock_session.get.side_effect = [resp_discovery, resp_main, resp_kev]

        resultado = extrair_dados_nist(total_desejado=2, max_por_pagina=2, buscar_mais_recentes=True)
        self.assertIsNotNone(resultado)
        ids_retornados = [v["cve"]["id"] for v in resultado["vulnerabilities"]]
        self.assertEqual(ids_retornados, ["CVE-2026-3001", "CVE-2026-3002", "CVE-2021-44228"])

    @patch("extract.requests.Session")
    def test_extrair_scores_epss_e_transform_enriquecido(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "data": [
                {"cve": "CVE-2026-4001", "epss": "0.94123", "percentile": "0.99871"},
                {"cve": "CVE-2026-4002", "epss": "0.01250", "percentile": "0.45100"}
            ]
        }
        mock_session.get.return_value = mock_resp

        mapa_epss = extrair_scores_epss(["CVE-2026-4001", "CVE-2026-4002", "CVE-2026-4001"])
        self.assertEqual(mapa_epss["CVE-2026-4001"]["epss"], 0.94123)
        self.assertEqual(mapa_epss["CVE-2026-4001"]["percentile"], 0.99871)

        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-4001",
                        "vulnStatus": "Analyzed",
                        "descriptions": [{"lang": "en", "value": "Remote code execution in Apache Struts"}],
                        "metrics": {
                            "cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
                        }
                    }
                }
            ]
        }
        vulns, _ = transformar_dados(payload, mapa_epss=mapa_epss)
        self.assertAlmostEqual(vulns[0]["epss_score"], 0.94123, places=5)
        self.assertAlmostEqual(vulns[0]["epss_percentile"], 0.99871, places=5)

    def test_chain_detector_isola_subprodutos_e_prioriza_kev(self):
        # Jenkins e Kubernetes pertencem a "GitLab / DevOps", mas não devem formar cadeia espúria sem CPE
        vulns = [
            {
                "id_cve": "CVE-2026-2001",
                "descricao": "Information disclosure in Jenkins allows reading sensitive files",
                "nota_cvss": 6.5,
                "severidade": "MEDIUM",
                "cwe": "CWE-200",
                "cisa_kev": False,
            },
            {
                "id_cve": "CVE-2026-2002",
                "descricao": "Remote code execution in Kubernetes cluster controller",
                "nota_cvss": 9.8,
                "severidade": "CRITICAL",
                "cwe": "CWE-94",
                "cisa_kev": False,
            },
            {
                "id_cve": "CVE-2026-2003",
                "descricao": "Authentication bypass in Ivanti Connect Secure gateway",
                "nota_cvss": 8.2,
                "severidade": "HIGH",
                "cwe": "CWE-287",
                "cpe_vendor": "ivanti",
                "cpe_product": "connect_secure",
                "cisa_kev": True,
            },
            {
                "id_cve": "CVE-2026-2004",
                "descricao": "Command injection in Ivanti Connect Secure admin interface",
                "nota_cvss": 9.1,
                "severidade": "CRITICAL",
                "cwe": "CWE-78",
                "cpe_vendor": "ivanti",
                "cpe_product": "connect_secure",
                "cisa_kev": True,
            },
            {
                "id_cve": "CVE-2026-2005",
                "descricao": "Information disclosure in Apache Tomcat servlet",
                "nota_cvss": 5.3,
                "severidade": "MEDIUM",
                "cwe": "CWE-200",
                "cpe_vendor": "apache",
                "cpe_product": "tomcat",
                "cisa_kev": False,
            },
            {
                "id_cve": "CVE-2026-2006",
                "descricao": "Remote code execution in Apache Tomcat",
                "nota_cvss": 9.8,
                "severidade": "CRITICAL",
                "cwe": "CWE-502",
                "cpe_vendor": "apache",
                "cpe_product": "tomcat",
                "cisa_kev": False,
            },
        ]
        self.assertEqual(extrair_subproduto(vulns[0]["descricao"]), "jenkins")
        self.assertEqual(extrair_subproduto(vulns[1]["descricao"]), "kubernetes")

        df = enriquecer_vulnerabilidades(vulns)
        self.assertEqual(df.loc[0, "subproduto"], "jenkins")
        self.assertEqual(df.loc[1, "subproduto"], "kubernetes")

        detector = ExploitChainDetector()
        detector.construir_grafo(df)
        chains = detector.detectar_chains(max_chains=10)

        # Nenhuma cadeia deve ligar Jenkins (CVE-2026-2001) a Kubernetes (CVE-2026-2002)
        for c in chains:
            self.assertNotEqual(c["cves"], ["CVE-2026-2001", "CVE-2026-2002"])

        # A cadeia com CISA KEV (Ivanti) deve ser priorizada em CHAIN-0001
        self.assertEqual(len(chains), 2)
        self.assertEqual(chains[0]["chain_id"], "CHAIN-0001")
        self.assertEqual(chains[0]["tecnologia"], "Ivanti / Pulse Secure")
        self.assertTrue(chains[0]["tem_kev"])
        self.assertEqual(chains[0]["kev_count"], 2)

        # Score composto sem KEV (5.3 -> 9.8) não satura artificialmente em 10.0
        self.assertLess(chains[1]["score_combinado"], 10.0)

        # WriteupBuilder propaga metadados KEV, CWE e mitigações contextuais
        writeup_kev = WriteupBuilder.construir_writeup(chains[0])
        self.assertTrue(writeup_kev["tem_kev"])
        self.assertIn("[CISA KEV]", writeup_kev["titulo"])
        self.assertEqual(writeup_kev["passos_ataque"][0]["cwe"], "CWE-287")
        self.assertTrue(writeup_kev["passos_ataque"][0]["cisa_kev"])
        self.assertTrue(any("CISA KEV" in m for m in writeup_kev["mitigacoes_recomendadas"]))

    def test_mitre_attack_e_priorizacao_epss_nas_chains(self):
        # Mapeamento MITRE ATT&CK por primitiva e override específico de CWE
        mitre_deser = obter_mitre_attack(AttackPrimitive.INJECTION_RCE, "CWE-502")
        self.assertEqual(mitre_deser["tactic_id"], "TA0002")
        self.assertEqual(mitre_deser["technique_id"], "T1203")

        mitre_privesc = obter_mitre_attack(AttackPrimitive.PRIV_ESC, "CWE-269")
        self.assertEqual(mitre_privesc["tactic_id"], "TA0004")
        self.assertEqual(mitre_privesc["technique_id"], "T1068")

        vulns = [
            {
                "id_cve": "CVE-2026-5001",
                "descricao": "Authentication bypass in Fortinet FortiOS SSL-VPN",
                "nota_cvss": 8.1,
                "severidade": "HIGH",
                "cwe": "CWE-287",
                "cpe_vendor": "fortinet",
                "cpe_product": "fortios",
                "cisa_kev": False,
                "epss_score": 0.92,
            },
            {
                "id_cve": "CVE-2026-5002",
                "descricao": "Remote command injection in Fortinet FortiOS CLI",
                "nota_cvss": 8.8,
                "severidade": "HIGH",
                "cwe": "CWE-78",
                "cpe_vendor": "fortinet",
                "cpe_product": "fortios",
                "cisa_kev": False,
                "epss_score": 0.89,
            },
            {
                "id_cve": "CVE-2026-5003",
                "descricao": "Authentication bypass in Oracle WebLogic console",
                "nota_cvss": 8.1,
                "severidade": "HIGH",
                "cwe": "CWE-287",
                "cpe_vendor": "oracle",
                "cpe_product": "weblogic",
                "cisa_kev": False,
                "epss_score": 0.01,
            },
            {
                "id_cve": "CVE-2026-5004",
                "descricao": "Remote code execution in Oracle WebLogic",
                "nota_cvss": 8.8,
                "severidade": "HIGH",
                "cwe": "CWE-502",
                "cpe_vendor": "oracle",
                "cpe_product": "weblogic",
                "cisa_kev": False,
                "epss_score": 0.01,
            },
        ]

        df = enriquecer_vulnerabilidades(vulns)
        detector = ExploitChainDetector()
        detector.construir_grafo(df)
        chains = detector.detectar_chains(max_chains=10)

        self.assertEqual(len(chains), 2)
        # Mesmo com CVSS idênticos, a cadeia Fortinet (EPSS 92%) deve superar Oracle (EPSS 1%)
        self.assertEqual(chains[0]["tecnologia"], "Fortinet / SonicWall")
        self.assertGreater(chains[0]["score_combinado"], chains[1]["score_combinado"])
        self.assertAlmostEqual(chains[0]["max_epss"], 0.92, places=2)

        writeup = WriteupBuilder.construir_writeup(chains[0])
        self.assertAlmostEqual(writeup["max_epss"], 0.92, places=2)
        self.assertGreaterEqual(len(writeup["taticas_mitre"]), 2)
        self.assertEqual(writeup["passos_ataque"][0]["mitre_attack"]["technique_id"], "T1078")
        self.assertEqual(writeup["passos_ataque"][1]["mitre_attack"]["technique_id"], "T1059")
        self.assertAlmostEqual(writeup["passos_ataque"][0]["epss_score"], 0.92, places=2)


if __name__ == "__main__":
    unittest.main()
