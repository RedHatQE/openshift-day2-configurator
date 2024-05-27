from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

import os
import base64
import logging
from typing import Any, Dict
from kubernetes.dynamic import DynamicClient

from ocp_resources.resource import ResourceEditor
from ocp_resources.configmap import ConfigMap
from ocp_resources.secret import Secret
from ocp_resources.pod import Pod
from ocp_resources.ingress_controller import IngressController
from ocp_resources.proxy import Proxy

from openshift_day2_configurator.utils.general import (
    verify_and_execute_configurator,
)
from rich.progress import Progress, TaskID
from openshift_day2_configurator.utils.resources import create_ocp_resource

CREATE_NEW_INGRESS_CERTIFICATE: str = "Create new Ingress certificate"
CREATE_INGRESS_CERTIFICATE_CONFIGMAP: str = "Create ConfigMap with the new Ingress certificate"
UPDATE_CLUSTER_PROXY_TRUSTED_CA: str = "Update cluster Proxy with the new Ingress certificate"
CREATE_WILDCARD_CERTIFICATE_TLS_SECRET: str = "Create wildcard certificate tls secret"
UPDATE_INGRESS_CONTROLLER_CERTIFICATE: str = "Update the IngressController certificate"
WAIT_ON_INGRESS_PODS_RESCHEDULE: str = "Wait on Ingress pods to reschedule"

OPENSHIFT_INGRESS_NAMESPACE: str = "openshift-ingress"
INGRESS_CERTIFICATE_CONFIGMAP_NAME: str = "custom-ca"

TIMEOUT_30MIN: int = 30 * 60


def get_ingress_certificate_from_file(cluster_domain: str) -> str:
    with open(f"*.{cluster_domain}.crt", "rb") as ingress_certificate_file:
        ingress_certificate = ingress_certificate_file.read().decode("utf-8")

    return ingress_certificate


def wait_for_ingress_pod_ready_condition(ingress_pod: Pod) -> None:
    ingress_pod.wait_for_condition(
        condition=Pod.Condition.READY,
        status=Pod.Condition.Status.TRUE,
        timeout=TIMEOUT_30MIN,
    )


def create_new_ingress_certificate(
    logger: logging.Logger,
    cluster_domain: str,
    ca_pem_file_path: str,
    ca_key_file_path: str,
) -> Dict[str, Dict[str, str | bool]]:
    logger.debug(CREATE_NEW_INGRESS_CERTIFICATE)

    missing_ca_files = [
        ca_file_path for ca_file_path in [ca_pem_file_path, ca_key_file_path] if not os.path.exists(ca_file_path)
    ]
    if missing_ca_files:
        logger.error(f"The following CA files does not exist: {missing_ca_files}")

    try:
        ingress_certificate_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        with open(f"{cluster_domain}.key", "wb") as ingress_certificate_key_file:
            ingress_certificate_key_file.write(
                ingress_certificate_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, f"{cluster_domain}"),
                ])
            )
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(f"*.{cluster_domain}"),
                ]),
                critical=False,
            )
            .sign(ingress_certificate_key, hashes.SHA256())
        )

        with open(f"{cluster_domain}.csr", "wb") as csr_file:
            csr_file.write(csr.public_bytes(serialization.Encoding.PEM))

        with open(ca_pem_file_path, "rb") as ca_cert_file:
            ca_cert = x509.load_pem_x509_certificate(ca_cert_file.read())

        with open(ca_key_file_path, "rb") as ca_key_file:
            ca_key = serialization.load_pem_private_key(ca_key_file.read(), password=None)

        certificate_builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=825))
        )

        certificate_extensions = [
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            x509.BasicConstraints(ca=False, path_length=None),
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            x509.SubjectAlternativeName([
                x509.DNSName(f"*.apps.{cluster_domain}"),
                x509.DNSName(cluster_domain),
                x509.DNSName(f"*.{cluster_domain}"),
            ]),
        ]

        for extension in certificate_extensions:
            certificate_builder = certificate_builder.add_extension(extension, critical=False)

        ingress_certificate = certificate_builder.sign(ca_key, hashes.SHA256())

        new_ingress_certificate_filename = f"*.{cluster_domain}.crt"
        with open(new_ingress_certificate_filename, "wb") as new_ingress_certificate_file:
            new_ingress_certificate_file.write(ingress_certificate.public_bytes(serialization.Encoding.PEM))

    except Exception as ex:
        logger.error(f"Failed to create {new_ingress_certificate_filename} Ingress certificate file: {ex}")
        return {CREATE_NEW_INGRESS_CERTIFICATE: {"res": False, "err": str(ex)}}

    return {CREATE_NEW_INGRESS_CERTIFICATE: {"res": True, "err": ""}}


def create_ingress_certificate_configmap(
    client: DynamicClient,
    logger: logging.Logger,
    cluster_domain: str,
) -> Dict[str, Dict[str, str]]:
    logger.debug(CREATE_INGRESS_CERTIFICATE_CONFIGMAP)

    ingress_certificate = get_ingress_certificate_from_file(cluster_domain=cluster_domain)

    return {
        CREATE_INGRESS_CERTIFICATE_CONFIGMAP: create_ocp_resource(
            ocp_resource=ConfigMap(
                client=client,
                name=INGRESS_CERTIFICATE_CONFIGMAP_NAME,
                namespace="openshift-config",
                data={
                    "ca-bundle.crt": base64.b64encode(ingress_certificate.encode()).decode(),
                },
            ),
            logger=logger,
        )
    }


def update_cluster_proxy_trusted_ca(
    client: DynamicClient,
    logger: logging.Logger,
) -> Dict[str, Dict[str, str | bool]]:
    logger.debug(UPDATE_CLUSTER_PROXY_TRUSTED_CA)

    cluster_proxy = Proxy(client=client, name="cluster")

    if not cluster_proxy.exists:
        cluster_proxy_not_exist_err: str = f"Cluster Proxy {cluster_proxy.name} does not exist"
        logger.error(cluster_proxy_not_exist_err)
        return {
            UPDATE_CLUSTER_PROXY_TRUSTED_CA: {
                "res": False,
                "err": cluster_proxy_not_exist_err,
            }
        }

    proxy_dict = {
        "trustedCA": {
            "name": INGRESS_CERTIFICATE_CONFIGMAP_NAME,
        }
    }

    try:
        ResourceEditor({cluster_proxy: {"spec": proxy_dict}}).update()
    except Exception as ex:
        logger.debug(f"Failed to update cluster proxy with error {ex}")
        return {UPDATE_CLUSTER_PROXY_TRUSTED_CA: {"res": False, "err": str(ex)}}

    return {UPDATE_CLUSTER_PROXY_TRUSTED_CA: {"res": True, "err": ""}}


def create_wildcard_certificate_tls_secret(
    client: DynamicClient,
    logger: logging.Logger,
    cluster_domain: str,
) -> Dict[str, Dict[str, str]]:
    logger.debug(CREATE_WILDCARD_CERTIFICATE_TLS_SECRET)

    ingress_certificate = get_ingress_certificate_from_file(cluster_domain=cluster_domain)

    with open(f"{cluster_domain}.key", "rb") as ingress_certificate_key_file:
        ingress_certificate_key = ingress_certificate_key_file.read().decode("utf-8")

    return {
        CREATE_WILDCARD_CERTIFICATE_TLS_SECRET: create_ocp_resource(
            ocp_resource=Secret(
                client=client,
                name=f"wildcard.{cluster_domain}",
                namespace=OPENSHIFT_INGRESS_NAMESPACE,
                data_dict={
                    "tls.crt": base64.b64encode(ingress_certificate.encode("utf-8")).decode("utf-8"),
                    "tls.key": base64.b64encode(ingress_certificate_key.encode("utf-8")).decode("utf-8"),
                },
                type="kubernetes.io/tls",
            ),
            logger=logger,
        )
    }


def update_ingress_controller_certificate(
    client: DynamicClient,
    logger: logging.Logger,
    cluster_domain: str,
) -> Dict[str, Dict[str, str | bool]]:
    logger.debug(UPDATE_INGRESS_CONTROLLER_CERTIFICATE)

    ingress_controller = IngressController(
        client=client, name="default", namespace=f"{OPENSHIFT_INGRESS_NAMESPACE}-operator"
    )

    if not ingress_controller.exists:
        ingress_controller_not_exist_err: str = f"IngressController {ingress_controller.name} does not exist"
        logger.error(ingress_controller_not_exist_err)
        return {
            UPDATE_INGRESS_CONTROLLER_CERTIFICATE: {
                "res": False,
                "err": ingress_controller_not_exist_err,
            }
        }

    ingress_controller_certificate_dict = {"defaultCertificate": {"name": f"wildcard.{cluster_domain}"}}

    try:
        ResourceEditor({ingress_controller: {"spec": ingress_controller_certificate_dict}}).update()
    except Exception as ex:
        logger.error(f"Failed to update ingress controller certificate: {ex}")
        return {UPDATE_INGRESS_CONTROLLER_CERTIFICATE: {"res": False, "err": str(ex)}}

    return {UPDATE_INGRESS_CONTROLLER_CERTIFICATE: {"res": True, "err": ""}}


def wait_on_ingress_pods_reschedule(
    client: DynamicClient,
    logger: logging.Logger,
) -> Dict[str, Dict[str, str | bool]]:
    logger.debug(WAIT_ON_INGRESS_PODS_RESCHEDULE)

    with ThreadPoolExecutor() as executor:
        futures = {
            executor.submit(wait_for_ingress_pod_ready_condition, ingress_pod): ingress_pod
            for ingress_pod in [
                pod for pod in Pod.get(dyn_client=client) if pod.namespace == OPENSHIFT_INGRESS_NAMESPACE
            ]
        }

        for future in as_completed(futures):
            ingress_pod = futures[future]
            try:
                future.result()  # Indicates if the pod reached Ready state
                logger.debug(f"Pod {ingress_pod.name} is in {Pod.Condition.READY} state.")
            except Exception as ex:
                logger.error(f"Pod {ingress_pod.name} failed to reach {Pod.Condition.READY} state: {ex}")
                return {WAIT_ON_INGRESS_PODS_RESCHEDULE: {"res": False, "err": str(ex)}}

    return {WAIT_ON_INGRESS_PODS_RESCHEDULE: {"res": True, "err": ""}}


def execute_ingress_configuration(
    config: Dict[str, Any],
    logger: logging.Logger,
    client: DynamicClient,
    progress: Progress | None = None,
) -> Dict[str, Dict[str, str | bool]]:
    logger.debug("Updating Ingress certificate")

    status_dict = {}
    task_id: TaskID | None = None

    cluster_domain: str | None = config.get("cluster_domain")

    tasks_dict = {
        CREATE_NEW_INGRESS_CERTIFICATE: {
            "func": create_new_ingress_certificate,
            "func_kwargs": {
                "cluster_domain": cluster_domain,
                "ca_pem_file_path": config.get("ca_pem_file_path"),
                "ca_key_file_path": config.get("ca_key_file_path"),
            },
        },
        CREATE_INGRESS_CERTIFICATE_CONFIGMAP: {
            "func": create_ingress_certificate_configmap,
            "func_kwargs": {
                "cluster_domain": cluster_domain,
                "client": client,
            },
        },
        UPDATE_CLUSTER_PROXY_TRUSTED_CA: {
            "func": update_cluster_proxy_trusted_ca,
            "func_kwargs": {
                "client": client,
            },
        },
        CREATE_WILDCARD_CERTIFICATE_TLS_SECRET: {
            "func": create_wildcard_certificate_tls_secret,
            "func_kwargs": {
                "cluster_domain": cluster_domain,
                "client": client,
            },
        },
        UPDATE_INGRESS_CONTROLLER_CERTIFICATE: {
            "func": update_ingress_controller_certificate,
            "func_kwargs": {
                "cluster_domain": cluster_domain,
                "client": client,
            },
        },
        WAIT_ON_INGRESS_PODS_RESCHEDULE: {
            "func": wait_on_ingress_pods_reschedule,
            "func_kwargs": {
                "client": client,
            },
        },
    }

    verify_and_execute_kwargs = {
        "config": config,
        "logger_obj": logger,
        "progress": progress,
        "logger": logger,
    }

    if progress:
        task_id = progress.add_task(description="  Updating Ingress certificate", total=len(tasks_dict))

    for _task, _func_config in tasks_dict.items():
        _kwargs: Dict[str, Any] = {**verify_and_execute_kwargs, **_func_config["func_kwargs"]}  # type: ignore[dict-item]
        status_dict.update(verify_and_execute_configurator(func=_func_config["func"], task_name=_task, **_kwargs))

        if progress and task_id is not None:
            progress.update(task_id, advance=1)

    if progress and task_id is not None:
        progress.update(task_id, advance=1)

    return status_dict
