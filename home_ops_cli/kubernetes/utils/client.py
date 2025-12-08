from kubernetes_asyncio import client, config  # type: ignore
from kubernetes_asyncio.dynamic import DynamicClient  # type: ignore
from kubernetes_asyncio.config import ConfigException
from contextlib import asynccontextmanager

@asynccontextmanager
async def dynamic_client():
    try:
        await config.load_kube_config()
        print("Configuration loaded from kubeconfig.")
    except ConfigException:
        try:
            config.load_incluster_config()
            print("Configuration loaded from in-cluster service account.")
        except ConfigException as e:
            raise RuntimeError(f"Could not load Kubernetes configuration: {e}")
    async with client.ApiClient() as api_client:
        dyn_client = await DynamicClient(api_client)
        yield dyn_client
