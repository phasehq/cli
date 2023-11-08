import kopf
import base64
import kubernetes.client
from kubernetes.client.rest import ApiException
from io import StringIO
import sys
from phase_cli.cmd.secrets.export import phase_secrets_env_export

@kopf.timer('secrets.phase.com', 'v1alpha1', 'phasesecrets', interval=4)
def fetch_secrets(spec, name, namespace, logger, **kwargs):
    try:
        # Extract information from the spec
        managed_secret_references = spec.get('managedSecretReferences')
        hostAPI = spec.get('hostAPI', 'https://console.phase.dev')

        # Initialize Kubernetes client
        api_instance = kubernetes.client.CoreV1Api()

        # Read the secret containing the service token
        secret_name = "phase-service-token"  # The name of your secret
        api_response = api_instance.read_namespaced_secret(secret_name, namespace)
        token = api_response.data['token']

        # Assuming your token is base64 encoded in the secret
        service_token = base64.b64decode(token).decode('utf-8')

        # Capture the output from the phase_secrets_env_export function
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        phase_secrets_env_export(phase_service_token=service_token, phase_service_host=hostAPI)
        sys.stdout.seek(0)
        output = sys.stdout.read()
        sys.stdout = old_stdout

        # Parse the captured output into a dictionary
        fetched_secrets_dict = dict(line.strip().split('=', 1) for line in output.splitlines() if line)

        # Construct the secret data for updating
        secret_data = {
            key: base64.b64encode(value.strip('"').encode()).decode('utf-8')
            for key, value in fetched_secrets_dict.items()
        }

        # Loop through the managed secrets and update or delete them
        for secret_reference in managed_secret_references:
            secret_name = secret_reference['secretName']
            secret_namespace = secret_reference.get('secretNamespace', namespace)

            try:
                # Check if secret exists
                existing_secret = api_instance.read_namespaced_secret(name=secret_name, namespace=secret_namespace)
                existing_secret_data_keys = set(existing_secret.data.keys())

                # Determine which keys are no longer present in fetched secrets
                keys_to_delete = existing_secret_data_keys - set(fetched_secrets_dict.keys())

                # If there are keys to delete, delete them from the existing secret data
                for key in keys_to_delete:
                    del existing_secret.data[key]

                # Update the secret with new data, and remove keys that are not part of fetched secrets
                api_instance.replace_namespaced_secret(name=secret_name, namespace=secret_namespace, body=kubernetes.client.V1Secret(
                    metadata=kubernetes.client.V1ObjectMeta(name=secret_name),
                    data=secret_data
                ))
                logger.info(f"Updated secret {secret_name} in namespace {secret_namespace}")

            except ApiException as e:
                if e.status == 404:
                    # Secret does not exist, so let's create it
                    api_instance.create_namespaced_secret(namespace=secret_namespace, body=kubernetes.client.V1Secret(
                        metadata=kubernetes.client.V1ObjectMeta(name=secret_name),
                        data=secret_data
                    ))
                    logger.info(f"Created secret {secret_name} in namespace {secret_namespace}")
                else:
                    logger.error(f"Failed to update secret {secret_name} in namespace {secret_namespace}: {e}")

        # Log a successful operation
        logger.info(f"Secrets for PhaseSecret {name} have been successfully updated in namespace {namespace}")


    except ApiException as e:
        if e.status == 403:
            logger.error(f"Permission denied when accessing secret {secret_name} in namespace {namespace}: {e}")
        else:
            logger.error(f"Failed to fetch secrets for PhaseSecret {name} in namespace {namespace}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error when handling PhaseSecret {name} in namespace {namespace}: {e}")
