import kopf
import base64
import kubernetes.client
from kubernetes.client.rest import ApiException
from datetime import datetime
from src.cmd.secrets.export import phase_secrets_env_export

@kopf.timer('secrets.phase.dev', 'v1alpha1', 'phasesecrets', interval=60)
def sync_secrets(spec, name, namespace, logger, **kwargs):
    try:
        # Extract information from the spec
        managed_secret_references = spec.get('managedSecretReferences', [])
        phase_host = spec.get('phaseHost', 'https://console.phase.dev')

        # Initialize Kubernetes client
        api_instance = kubernetes.client.CoreV1Api()

        # Fetch and process the Phase service token from the Kubernetes managed secret
        service_token_secret_name = spec.get('authentication', {}).get('serviceToken', {}).get('serviceTokenSecretReference', {}).get('secretName', 'phase-service-token')
        api_response = api_instance.read_namespaced_secret(service_token_secret_name, namespace)
        token = api_response.data['token']
        service_token = base64.b64decode(token).decode('utf-8')

        # Fetch secrets from the Phase application
        fetched_secrets_dict = phase_secrets_env_export(
            phase_service_token=service_token,
            phase_service_host=phase_host,
            export_type='k8'
        )

        # Update the Kubernetes managed secrets -- update if: available, create if: unavailable.
        for secret_reference in managed_secret_references:
            secret_name = secret_reference['secretName']
            secret_namespace = secret_reference.get('secretNamespace', namespace)

            try:
                # Check if the secret exists in Kubernetes
                api_instance.read_namespaced_secret(name=secret_name, namespace=secret_namespace)

                # Update the secret with the new data
                api_instance.replace_namespaced_secret(
                    name=secret_name,
                    namespace=secret_namespace,
                    body=kubernetes.client.V1Secret(
                        metadata=kubernetes.client.V1ObjectMeta(name=secret_name),
                        data=fetched_secrets_dict
                    )
                )
                logger.info(f"Updated secret {secret_name} in namespace {secret_namespace}")
            except ApiException as e:
                if e.status == 404:
                    # Secret does not exist in kubernetes, create it
                    api_instance.create_namespaced_secret(
                        namespace=secret_namespace,
                        body=kubernetes.client.V1Secret(
                            metadata=kubernetes.client.V1ObjectMeta(name=secret_name),
                            data=fetched_secrets_dict
                        )
                    )
                    logger.info(f"Created secret {secret_name} in namespace {secret_namespace}")
                else:
                    logger.error(f"Failed to update secret {secret_name} in namespace {secret_namespace}: {e}")

        logger.info(f"Secrets for PhaseSecret {name} have been successfully updated in namespace {namespace}")

    except ApiException as e:
        logger.error(f"Failed to fetch secrets for PhaseSecret {name} in namespace {namespace}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error when handling PhaseSecret {name} in namespace {namespace}: {e}")
