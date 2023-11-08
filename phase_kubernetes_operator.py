import kopf
import base64
import kubernetes.client
from kubernetes.client.rest import ApiException
from phase_cli.cmd.secrets.export import phase_secrets_env_export

@kopf.timer('secrets.phase.com', 'v1alpha1', 'phasesecrets', interval=60)
def fetch_secrets(spec, name, namespace, logger, **kwargs):
    try:
        # Extract information from the spec
        managed_secret_references = spec.get('managedSecretReferences')
        hostAPI = spec.get('hostAPI', 'https://console.phase.dev')

        # Initialize Kubernetes client
        api_instance = kubernetes.client.CoreV1Api()

        # Read the secret containing the service token
        secret_name = spec.get('serviceTokenSecretName', 'phase-service-token')
        api_response = api_instance.read_namespaced_secret(secret_name, namespace)
        token = api_response.data['token']

        # Decode the service token
        service_token = base64.b64decode(token).decode('utf-8')

        # Fetch the secrets using the updated phase_secrets_env_export function
        fetched_secrets_dict = phase_secrets_env_export(
            phase_service_token=service_token,
            phase_service_host=hostAPI,
            export_type='k8'
        )

        # Loop through the managed secrets and update or create them
        for secret_reference in managed_secret_references:
            secret_name = secret_reference['secretName']
            secret_namespace = secret_reference.get('secretNamespace', namespace)

            try:
                # Check if the secret exists
                api_instance.read_namespaced_secret(name=secret_name, namespace=secret_namespace)

                # Replace the secret with the new data
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
                    # Secret does not exist, create it
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

        # Log a successful operation
        logger.info(f"Secrets for PhaseSecret {name} have been successfully updated in namespace {namespace}")

    except ApiException as e:
        logger.error(f"Failed to fetch secrets for PhaseSecret {name} in namespace {namespace}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error when handling PhaseSecret {name} in namespace {namespace}: {e}")
