"""
E2E test for in-place ExternalProvider auth Secret rotation under Praxis ExtProc.

Covers RHOAIENG-97467: when the provider auth Secret is updated in place (same
name/key, new value), external-provider inference must keep working through the
Praxis ExtProc dataplane *without* deleting the ExtProc pod or the ExternalModel.
This guards against the IPP resolver stall that was observed after credential
updates (``demo.sh`` historically marked rotation NOT_DEMONSTRATED).

The flow:
  1. Confirm the default payload-processing stack is praxis-extproc (skip otherwise).
  2. Stand up an ExternalProvider/ExternalModel egress route backed by a
     credential Secret and prove authenticated egress is reachable.
  3. Record the current ExtProc pod UIDs (payload-processing + pre-processing).
  4. Rotate the provider Secret in place — same name, same key, new value.
  5. Prove egress is still reachable (the resolver did not stall) while the ExtProc
     pods were never replaced and the ExternalModel was never deleted/recreated.

CAVEAT: the e2e upstream (httpbingo) does not validate the injected credential,
so this proves the data plane keeps serving across an in-place Secret rotation
without a restart — not that a bad credential would be rejected. The regression
being guarded is the resolver stall, which is exactly a continued-success +
no-restart signal.
"""

from __future__ import annotations

import logging
import os
import time

import pytest
import requests
from multitenancy_helpers import (
    GATEWAY_NAMESPACE,
    LABEL_TENANT_INSTANCE,
    _oc_run,
    extproc_deployment_uses_praxis,
)
from test_helper import (
    MODEL_NAMESPACE,
    RECONCILE_WAIT,
    TLS_VERIFY,
    _apply_cr,
    _check_ipp_pods_deployed,
    _delete_cr,
    _get_cr,
    _is_transient_gateway_response,
    _ns,
    _wait_for_httproute_accepted,
    _wait_for_maas_auth_policy_phase,
    _wait_for_maas_subscription_phase,
    _wait_for_model_ready,
)

log = logging.getLogger(__name__)

# ─── Configuration ──────────────────────────────────────────────────────────

EXTERNAL_ENDPOINT = os.environ.get(
    "E2E_EXTERNAL_ENDPOINT",
    os.environ.get("E2E_SIMULATOR_ENDPOINT", "httpbingo.org"),
)


def _subscription_ns():
    return os.environ.get("E2E_SUBSCRIPTION_NAMESPACE", _ns())


TARGET_MODEL = "gpt-3.5-turbo"

EXTERNAL_MODEL_NAME = "e2e-rotation-external-model"
EXTERNAL_PROVIDER_NAME = "e2e-rotation-external-provider"
SECRET_NAME = f"{EXTERNAL_MODEL_NAME}-api-key"
SECRET_KEY = "api-key"
SUBSCRIPTION_NAME = "e2e-rotation-subscription"
AUTH_POLICY_NAME = "e2e-rotation-access"

# Same name/key, new value — the "in place" rotation the AC describes.
SECRET_VALUE_V1 = "e2e-rotation-key-v1"
SECRET_VALUE_V2 = "e2e-rotation-key-v2"

# Canonical inference.opendatahub.io CRDs (see test_external_models.py for the
# group/kind rationale).
EXTERNAL_MODEL_KIND = "externalmodels.inference.opendatahub.io"
EXTERNAL_PROVIDER_KIND = "externalproviders.inference.opendatahub.io"

# Default-tenant praxis ExtProc Deployments (unsuffixed) in the gateway namespace.
PROCESSING_DEPLOYMENT = "payload-processing"
PRE_PROCESSING_DEPLOYMENT = "payload-pre-processing"

EGRESS_POLL_TIMEOUT = max(RECONCILE_WAIT * 6, 90)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _check_external_endpoint_reachable() -> bool:
    """Verify the external endpoint is reachable. Skip tests if not."""
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{EXTERNAL_ENDPOINT}/get", timeout=10, verify=False)
            if r.status_code == 200:
                return True
        except Exception:
            pass
    return False


pytestmark = [
    pytest.mark.serial,
    pytest.mark.skipif(
        not _check_external_endpoint_reachable(),
        reason=f"External endpoint {EXTERNAL_ENDPOINT} is not reachable (disconnected environment?)",
    ),
    pytest.mark.xdist_group("tenant_ipp"),
]


def _skip_unless_default_praxis():
    if not _check_ipp_pods_deployed():
        pytest.skip("Default payload-processing stack is not ready")
    if not extproc_deployment_uses_praxis(PROCESSING_DEPLOYMENT):
        pytest.skip("default tenant payload-processing is not praxis-extproc")


def _extproc_pod_uids(deployment: str) -> set[str]:
    """UIDs of a Deployment's current pods, to prove rotation did not replace them."""
    result = _oc_run(
        [
            "get",
            "pods",
            "-n",
            GATEWAY_NAMESPACE,
            "-l",
            f"{LABEL_TENANT_INSTANCE}={deployment}",
            "-o",
            "jsonpath={.items[*].metadata.uid}",
        ]
    )
    return {uid for uid in (result.stdout or "").split() if uid}


def _apply_provider_secret(value: str):
    """Create/replace the provider credential Secret in place (same name/key)."""
    _apply_cr(
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": SECRET_NAME,
                "namespace": MODEL_NAMESPACE,
                # The apikey-injection plugin's secret store only watches Secrets
                # carrying this label; without it credential lookups silently fail.
                "labels": {"inference.llm-d.ai/ipp-managed": "true"},
            },
            "type": "Opaque",
            "stringData": {SECRET_KEY: value},
        }
    )


def _poll_egress_reachable(url: str, headers: dict, body: dict, *, timeout: int) -> requests.Response:
    """POST until the request clears auth and reaches the external upstream.

    Success = a non-auth response that is not a transient gateway/Authorino
    flake. httpbingo returns 404 for ``/v1/chat/completions``, which still proves
    the request left the cluster. 401/403 means auth blocked; empty 401 and
    proxy-style 500/503 are retried (see ``_is_transient_gateway_response``).
    """
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            last = requests.post(url, headers=headers, json=body, timeout=30, verify=TLS_VERIFY)
        except requests.RequestException as exc:
            log.info("Egress poll transient request error: %s", exc)
            time.sleep(2)
            continue
        if last.status_code not in (401, 403) and not _is_transient_gateway_response(last):
            return last
        log.info("Egress poll got %d, retrying...", last.status_code)
        time.sleep(2)
    status = last.status_code if last is not None else "no response"
    raise AssertionError(f"External egress never became reachable (last status: {status})")


# ─── Fixture: external provider + model backed by a credential Secret ─────────

@pytest.fixture(scope="module")
def rotation_setup(gateway_url, headers, api_keys_base_url):
    """Stand up an external egress route backed by a rotatable credential Secret."""
    _skip_unless_default_praxis()

    log.info("Setting up external provider rotation fixture (endpoint: %s)...", EXTERNAL_ENDPOINT)
    try:
        _apply_provider_secret(SECRET_VALUE_V1)

        _apply_cr(
            {
                "apiVersion": "inference.opendatahub.io/v1alpha1",
                "kind": "ExternalProvider",
                "metadata": {"name": EXTERNAL_PROVIDER_NAME, "namespace": MODEL_NAMESPACE},
                "spec": {
                    "provider": "openai",
                    "endpoint": EXTERNAL_ENDPOINT,
                    "auth": {
                        "type": "simple",
                        "secretRef": {"name": SECRET_NAME},
                    },
                },
            }
        )

        _apply_cr(
            {
                "apiVersion": "inference.opendatahub.io/v1alpha1",
                "kind": "ExternalModel",
                "metadata": {"name": EXTERNAL_MODEL_NAME, "namespace": MODEL_NAMESPACE},
                "spec": {
                    "externalProviderRefs": [
                        {
                            "ref": {"name": EXTERNAL_PROVIDER_NAME},
                            "targetModel": TARGET_MODEL,
                            "apiFormat": "openai-chat",
                            "path": "/v1/chat/completions",
                        },
                    ],
                },
            }
        )

        _apply_cr(
            {
                "apiVersion": "maas.opendatahub.io/v1alpha1",
                "kind": "MaaSModelRef",
                "metadata": {
                    "name": EXTERNAL_MODEL_NAME,
                    "namespace": MODEL_NAMESPACE,
                    "annotations": {
                        "maas.opendatahub.io/endpoint": EXTERNAL_ENDPOINT,
                        "maas.opendatahub.io/provider": "openai",
                    },
                },
                "spec": {
                    "modelRef": {"kind": "ExternalModel", "name": EXTERNAL_MODEL_NAME},
                },
            }
        )

        _apply_cr(
            {
                "apiVersion": "maas.opendatahub.io/v1alpha1",
                "kind": "MaaSAuthPolicy",
                "metadata": {"name": AUTH_POLICY_NAME, "namespace": _subscription_ns()},
                "spec": {
                    "modelRefs": [{"name": EXTERNAL_MODEL_NAME, "namespace": MODEL_NAMESPACE}],
                    "subjects": {"groups": [{"name": "system:authenticated"}]},
                },
            }
        )

        _apply_cr(
            {
                "apiVersion": "maas.opendatahub.io/v1alpha1",
                "kind": "MaaSSubscription",
                "metadata": {"name": SUBSCRIPTION_NAME, "namespace": _subscription_ns()},
                "spec": {
                    "owner": {"groups": [{"name": "system:authenticated"}]},
                    "modelRefs": [
                        {
                            "name": EXTERNAL_MODEL_NAME,
                            "namespace": MODEL_NAMESPACE,
                            "tokenRateLimits": [{"limit": 10000, "window": "1h"}],
                        },
                    ],
                },
            }
        )

        _wait_for_maas_auth_policy_phase(AUTH_POLICY_NAME, namespace=_subscription_ns())
        _wait_for_maas_subscription_phase(SUBSCRIPTION_NAME, namespace=_subscription_ns())
        _wait_for_httproute_accepted(EXTERNAL_MODEL_NAME, namespace=MODEL_NAMESPACE)
        _wait_for_model_ready(EXTERNAL_MODEL_NAME, namespace=MODEL_NAMESPACE, timeout=120)

        log.info("Creating API key for rotation tests...")
        r = requests.post(
            api_keys_base_url,
            headers=headers,
            json={"name": "e2e-rotation-key", "subscription": SUBSCRIPTION_NAME},
            timeout=30,
            verify=TLS_VERIFY,
        )
        if r.status_code not in (200, 201):
            pytest.fail(f"Failed to create API key: {r.status_code} {r.text}")
        api_key = r.json().get("key")
        if not api_key:
            pytest.fail("API key creation response missing 'key' field")

        yield {"api_key": api_key, "gateway_url": gateway_url}
    finally:
        log.info("Cleaning up external provider rotation fixtures...")
        _delete_cr("maasauthpolicy", AUTH_POLICY_NAME, _subscription_ns())
        _delete_cr("maassubscription", SUBSCRIPTION_NAME, _subscription_ns())
        _delete_cr("maasmodelref", EXTERNAL_MODEL_NAME, MODEL_NAMESPACE)
        _delete_cr(EXTERNAL_MODEL_KIND, EXTERNAL_MODEL_NAME, MODEL_NAMESPACE)
        _delete_cr(EXTERNAL_PROVIDER_KIND, EXTERNAL_PROVIDER_NAME, MODEL_NAMESPACE)
        _delete_cr("secret", SECRET_NAME, MODEL_NAMESPACE)


# ─── Test ──────────────────────────────────────────────────────────────────

class TestPraxisExtProcSecretRotation:
    """In-place provider Secret rotation keeps egress alive (RHOAIENG-97467)."""

    def _egress_url(self, setup) -> str:
        return f"{setup['gateway_url']}/{MODEL_NAMESPACE}/{EXTERNAL_MODEL_NAME}/v1/chat/completions"

    def _request(self, setup):
        url = self._egress_url(setup)
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {setup['api_key']}",
        }
        body = {"model": EXTERNAL_MODEL_NAME, "messages": [{"role": "user", "content": "hello"}]}
        return url, headers, body

    def test_in_place_secret_rotation_keeps_egress_without_extproc_restart(self, rotation_setup):
        setup = rotation_setup
        url, headers, body = self._request(setup)

        # 1. Baseline: egress is reachable through the praxis ExtProc dataplane.
        before = _poll_egress_reachable(url, headers, body, timeout=EGRESS_POLL_TIMEOUT)
        log.info("Baseline egress reachable: HTTP %d", before.status_code)

        # 2. Snapshot the ExtProc pods that must survive the rotation untouched.
        before_uids = {
            d: _extproc_pod_uids(d)
            for d in (PROCESSING_DEPLOYMENT, PRE_PROCESSING_DEPLOYMENT)
        }
        for deployment, uids in before_uids.items():
            assert uids, f"no {deployment} pods found before rotation"

        # 3. Rotate the credential in place: same name, same key, new value.
        _apply_provider_secret(SECRET_VALUE_V2)
        secret = _get_cr("secret", SECRET_NAME, MODEL_NAMESPACE)
        assert secret is not None, "provider Secret vanished after in-place rotation"
        log.info("Provider Secret rotated in place (same name/key, new value)")

        # Give the ExtProc secret store a beat to observe the updated value.
        time.sleep(RECONCILE_WAIT)

        # 4. Egress must still be reachable — the resolver did not stall.
        after = _poll_egress_reachable(url, headers, body, timeout=EGRESS_POLL_TIMEOUT)
        log.info("Egress still reachable after rotation: HTTP %d", after.status_code)

        # 5a. The ExtProc pods were never restarted.
        for deployment, uids in before_uids.items():
            after_uids = _extproc_pod_uids(deployment)
            assert uids <= after_uids, (
                f"{deployment} pods were replaced during in-place rotation "
                f"(before={uids}, after={after_uids}); rotation must not restart ExtProc"
            )

        # 5b. The ExternalModel was never deleted/recreated.
        assert _get_cr(EXTERNAL_MODEL_KIND, EXTERNAL_MODEL_NAME, MODEL_NAMESPACE) is not None, (
            "ExternalModel disappeared during in-place Secret rotation"
        )
