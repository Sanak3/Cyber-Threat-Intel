import sys
import os
import unittest
from unittest.mock import patch, MagicMock
import pandas as pd

# Adiciona o diretório data_pipeline ao path para importação direta
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data_pipeline")))

from extract import extrair_dados_nist
from transform import extrair_metricas_cvss, sanitizar_texto, transformar_dados
from ml_engine.primitives import (
    AttackPrimitive,
    extrair_primitiva,
    extrair_tecnologia,
    enriquecer_vulnerabilidades
)
from ml_engine.chain_detector import ExploitChainDetector
from ml_engine.clusterizer import CVEClusterizer


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


if __name__ == "__main__":
    unittest.main()
