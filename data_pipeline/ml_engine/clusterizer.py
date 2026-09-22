import os
from typing import List, Dict, Tuple, Optional
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
import joblib


# Diretório padrão para persistência dos modelos treinados
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
MODEL_FILE = os.path.join(MODELS_DIR, "cve_clusterizer.joblib")


class CVEClusterizer:
    """
    Clusterizador Semântico de Vulnerabilidades utilizando TF-IDF e K-Means.
    Descobre agrupamentos temáticos de vulnerabilidades e nomeia clusters
    automaticamente com base nos termos mais relevantes de cada centroide.
    """

    def __init__(self, n_clusters: int = 6, max_features: int = 1500):
        self.n_clusters = n_clusters
        self.max_features = max_features
        self.vectorizer: Optional[TfidfVectorizer] = None
        self.model: Optional[KMeans] = None
        self.cluster_labels: Dict[int, str] = {}
        self.is_fitted: bool = False

    def _gerar_nome_cluster(self, top_termos: List[str]) -> str:
        """
        Gera um rótulo humanizado para o cluster com base nos top termos.
        """
        termos_set = set(top_termos)

        if any(t in termos_set for t in ["overflow", "buffer", "memory", "heap", "stack", "out"]):
            return "Memory Corruption & Buffer Overflow"
        if any(t in termos_set for t in ["sql", "injection", "sqli"]):
            return "Database & SQL Injection"
        if any(t in termos_set for t in ["xss", "cross", "scripting", "site"]):
            return "Web Application & Cross-Site Scripting (XSS)"
        if any(t in termos_set for t in ["privilege", "escalation", "root", "elevation"]):
            return "Privilege Escalation & Access Gain"
        if any(t in termos_set for t in ["bypass", "authentication", "unauthenticated", "token"]):
            return "Authentication & Access Control Bypass"
        if any(t in termos_set for t in ["service", "denial", "dos", "crash", "loop"]):
            return "Denial of Service & Resource Exhaustion"
        if any(t in termos_set for t in ["traversal", "directory", "file", "arbitrary"]):
            return "Path Traversal & Arbitrary File Access"
        if any(t in termos_set for t in ["remote", "code", "execution", "execute"]):
            return "Remote Code Execution (RCE)"

        # Fallback usando os 3 primeiros termos
        return " / ".join([t.capitalize() for t in top_termos[:3]])

    def fit(self, textos: List[str]) -> "CVEClusterizer":
        """
        Treina o vetorizador TF-IDF e o modelo K-Means sobre as descrições.
        """
        textos_validos = [str(t).strip() for t in textos if str(t).strip()]
        if len(textos_validos) < self.n_clusters:
            raise ValueError(f"Quantidade insuficiente de textos ({len(textos_validos)}) para {self.n_clusters} clusters.")

        print(f"[+] [ML Clusterizer] Vetorizando {len(textos_validos):,} textos com TF-IDF (max_features={self.max_features})...")
        self.vectorizer = TfidfVectorizer(
            max_features=self.max_features,
            stop_words="english",
            ngram_range=(1, 2),
            min_df=2,
            max_df=0.85
        )
        X = self.vectorizer.fit_transform(textos_validos)

        print(f"[+] [ML Clusterizer] Ajustando K-Means com k={self.n_clusters} clusters...")
        self.model = KMeans(n_clusters=self.n_clusters, random_state=42, n_init=5)
        cluster_ids = self.model.fit_predict(X)

        # Mapeamento dos termos mais importantes por cluster
        termos = np.array(self.vectorizer.get_feature_names_out())
        centroides = self.model.cluster_centers_

        self.cluster_labels = {}
        for idx_cluster in range(self.n_clusters):
            # Índices dos top 5 termos com maior peso no centroide
            top_indices = centroides[idx_cluster].argsort()[::-1][:5]
            top_termos = list(termos[top_indices])
            rotulo = self._gerar_nome_cluster(top_termos)
            self.cluster_labels[idx_cluster] = rotulo

        # Avaliação de qualidade de agrupamento com Silhouette Score (amostra até 2000 pontos)
        sample_size = min(len(textos_validos), 2000)
        if sample_size > self.n_clusters:
            try:
                score_sil = silhouette_score(X[:sample_size], cluster_ids[:sample_size])
                print(f"[+] [ML Clusterizer] Silhouette Score (qualidade dos clusters): {score_sil:.4f}")
            except Exception:
                pass

        self.is_fitted = True
        return self

    def predict(self, textos: List[str]) -> Tuple[List[int], List[str]]:
        """
        Classifica novos textos nos clusters previamente treinados.
        """
        if not self.is_fitted or not self.vectorizer or not self.model:
            raise RuntimeError("O modelo ainda não foi treinado nem carregado.")

        textos_str = [str(t) if t else "" for t in textos]
        X = self.vectorizer.transform(textos_str)
        cluster_ids = self.model.predict(X).tolist()
        cluster_names = [self.cluster_labels.get(cid, f"Cluster {cid}") for cid in cluster_ids]

        return cluster_ids, cluster_names

    def fit_predict(self, df: pd.DataFrame, coluna_texto: str = "descricao") -> pd.DataFrame:
        """
        Recebe um DataFrame, treina nos textos e adiciona 'cluster_id' e 'cluster_label'.
        """
        textos = df[coluna_texto].fillna("").tolist()
        self.fit(textos)
        cluster_ids, cluster_names = self.predict(textos)

        df_result = df.copy()
        df_result["cluster_id"] = cluster_ids
        df_result["cluster_label"] = cluster_names
        return df_result

    def save(self, filepath: str = MODEL_FILE) -> None:
        """
        Salva o modelo treinado em disco usando joblib.
        """
        if not self.is_fitted:
            raise RuntimeError("Não é possível salvar um modelo não treinado.")

        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        payload = {
            "n_clusters": self.n_clusters,
            "max_features": self.max_features,
            "vectorizer": self.vectorizer,
            "model": self.model,
            "cluster_labels": self.cluster_labels
        }
        joblib.dump(payload, filepath)
        print(f"[+] [ML Clusterizer] Modelo persistido com sucesso em: {filepath}")

    @classmethod
    def load(cls, filepath: str = MODEL_FILE) -> "CVEClusterizer":
        """
        Carrega o modelo salvo em disco.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Arquivo de modelo não encontrado: {filepath}")

        payload = joblib.load(filepath)
        instancia = cls(n_clusters=payload["n_clusters"], max_features=payload["max_features"])
        instancia.vectorizer = payload["vectorizer"]
        instancia.model = payload["model"]
        instancia.cluster_labels = payload["cluster_labels"]
        instancia.is_fitted = True
        return instancia
