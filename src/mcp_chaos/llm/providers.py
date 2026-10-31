"""LLM provider registry for the real-LLM example agent.

Everything except Anthropic is reached through an OpenAI-compatible /chat/completions endpoint.
Base URLs below were written from memory of each vendor's docs and have NOT been exercised against the real
services by this project: verify them (and the model names you put in .env) before relying on them.
Every base URL can be overridden with <PREFIX>_BASE_URL.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Provider:
    name: str
    key_env: str
    base_url: str
    protocol: str = "openai"  # or "anthropic"
    region: str = "global"
    note: str = ""

    @property
    def prefix(self) -> str:
        return self.key_env.removesuffix("_API_KEY")


PROVIDERS: dict[str, Provider] = {p.name: p for p in [
    Provider("anthropic", "ANTHROPIC_API_KEY", "https://api.anthropic.com", "anthropic"),
    Provider("openai", "OPENAI_API_KEY", "https://api.openai.com/v1"),
    Provider("gemini", "GEMINI_API_KEY", "https://generativelanguage.googleapis.com/v1beta/openai", note="Google's OpenAI-compatible endpoint"),
    Provider("xai", "XAI_API_KEY", "https://api.x.ai/v1"),
    Provider("mistral", "MISTRAL_API_KEY", "https://api.mistral.ai/v1"),
    Provider("groq", "GROQ_API_KEY", "https://api.groq.com/openai/v1"),
    Provider("together", "TOGETHER_API_KEY", "https://api.together.xyz/v1"),
    Provider("openrouter", "OPENROUTER_API_KEY", "https://openrouter.ai/api/v1", note="routes to many vendors"),
    Provider("deepseek", "DEEPSEEK_API_KEY", "https://api.deepseek.com", region="china"),
    Provider("qwen", "DASHSCOPE_API_KEY", "https://dashscope.aliyuncs.com/compatible-mode/v1", region="china",
             note="Alibaba Qwen via DashScope; international endpoint is dashscope-intl.aliyuncs.com"),
    Provider("moonshot", "MOONSHOT_API_KEY", "https://api.moonshot.cn/v1", region="china", note="Kimi"),
    Provider("zhipu", "ZHIPU_API_KEY", "https://open.bigmodel.cn/api/paas/v4", region="china", note="GLM"),
    Provider("baidu", "QIANFAN_API_KEY", "https://qianfan.baidubce.com/v2", region="china", note="ERNIE via Qianfan"),
    Provider("minimax", "MINIMAX_API_KEY", "https://api.minimax.chat/v1", region="china"),
    Provider("yi", "YI_API_KEY", "https://api.lingyiwanwu.com/v1", region="china", note="01.AI"),
    Provider("custom", "CUSTOM_API_KEY", "", note="any OpenAI-compatible server (set CUSTOM_BASE_URL and CUSTOM_MODEL), e.g. a local vLLM/Ollama"),
]}


def resolve(name: str) -> tuple[Provider, str, str, str]:
    """Return (provider, api_key, base_url, model) from the environment. Raises SystemExit with guidance if unset."""
    if name not in PROVIDERS:
        raise SystemExit(f"unknown provider {name!r}; choose from: {', '.join(PROVIDERS)}")
    p = PROVIDERS[name]
    key = os.environ.get(p.key_env, "")
    base = os.environ.get(f"{p.prefix}_BASE_URL", p.base_url)
    model = os.environ.get(f"{p.prefix}_MODEL", "")
    if not key and name != "custom":
        raise SystemExit(f"{p.key_env} is not set (add it to .env and run with --env-file .env --pass-env {p.key_env})")
    if not base:
        raise SystemExit(f"{p.prefix}_BASE_URL is not set")
    if not model:
        raise SystemExit(f"{p.prefix}_MODEL is not set: put a model name from the vendor's current docs in .env")
    return p, key, base.rstrip("/"), model


def configured(environ=os.environ) -> dict[str, bool]:
    """Which providers have a key set. Never returns the key itself."""
    return {n: bool(environ.get(p.key_env)) for n, p in PROVIDERS.items()}
