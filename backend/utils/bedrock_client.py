"""Bedrock Client Factory — Creates boto3 clients with Bearer Token authentication."""

import boto3
import logging
from config import Config

logger = logging.getLogger(__name__)

_bedrock_client = None


def get_bedrock_client():
    """Get or create a Bedrock Runtime client with Bearer Token auth."""
    global _bedrock_client
    if _bedrock_client is not None:
        return _bedrock_client

    bearer_token = Config.AWS_BEARER_TOKEN
    region = Config.AWS_REGION

    if not bearer_token:
        raise ValueError("AWS_BEARER_TOKEN_BEDROCK is not set")

    logger.info(f"Creating Bedrock client for region: {region}")

    # Create client with dummy credentials — we override auth with Bearer token
    client = boto3.client(
        "bedrock-runtime",
        region_name=region,
        aws_access_key_id="not-used",
        aws_secret_access_key="not-used",
    )

    # Register event handler to replace SigV4 with Bearer token auth
    def _inject_bearer_token(request, **kwargs):
        request.headers["Authorization"] = f"Bearer {bearer_token}"
        # Remove AWS SigV4 headers that boto3 adds
        keys_to_remove = [
            k for k in list(request.headers.keys())
            if k.lower().startswith("x-amz")
        ]
        for k in keys_to_remove:
            del request.headers[k]

    client.meta.events.register("before-send.bedrock-runtime.*", _inject_bearer_token)

    _bedrock_client = client
    logger.info("Bedrock client created with Bearer Token auth")
    return _bedrock_client


def get_llm(temperature=0, max_tokens=2000):
    """Get a LangChain ChatBedrockConverse LLM instance."""
    from langchain_aws import ChatBedrockConverse

    client = get_bedrock_client()
    return ChatBedrockConverse(
        client=client,
        model=Config.BEDROCK_MODEL,
        region_name=Config.AWS_REGION,
        temperature=temperature,
        max_tokens=max_tokens,
    )


def get_embeddings():
    """Get a LangChain BedrockEmbeddings instance."""
    from langchain_aws import BedrockEmbeddings

    client = get_bedrock_client()
    return BedrockEmbeddings(
        client=client,
        model_id=Config.EMBEDDING_MODEL,
        region_name=Config.AWS_REGION,
    )
