import sys
import os
import unittest
import pandas as pd

# Adiciona o diretório data_pipeline ao path para importação direta
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data_pipeline")))

from transform import extrair_metricas_cvss, sanitizar_texto
from ml_engine.primitives import (
    AttackPrimitive,
    extrair_primitiva,
    extrair_tecnologia,
    enriquecer_vulnerabilidades
)
from ml_engine.chain_detector import ExploitChainDetector


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


if __name__ == "__main__":
    unittest.main()
