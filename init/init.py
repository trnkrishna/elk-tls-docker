import requests
from urllib3.exceptions import InsecureRequestWarning
from requests.auth import HTTPBasicAuth
import os
import shutil
import time

# Mandatory Variables
MAIN_IP = os.environ.get("MAIN_IP", "kibana")
PROJECT_PATH=os.getenv("PROJECT_PATH", "")

# Derived and Non-Mandatory Variables
KIBANA_IP = os.getenv("KIBANA_IP", "kibana")
ES_IP = os.getenv("ES_IP", "elasticsearch")
INSTALL_SCRIPTS_TEMPLATE_PATH = os.path.join(PROJECT_PATH, "init/templates/")
CA_PATH = os.path.join(PROJECT_PATH, "secrets/certificate_authority/ca/ca.crt")
INSTALL_SCRIPTS_FINAL_PATH = os.path.join(PROJECT_PATH, "init/agent-setups/")
URL = "https://" + KIBANA_IP + ":5601/api/fleet"

# Suppress on[ly the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


def get_request_session():
    session = requests.Session()
    session.verify = False
    session.auth = HTTPBasicAuth("elastic", "changeme")
    session.headers = {"kbn-xsrf": "Excepteur Lorem anim sint"}

    return session


def get_default_system_policy_id():
    # Get Policies ID
    r = get_request_session().get(url=URL + "/package_policies")
    r.raise_for_status()

    # extracting data in json format
    json_data = r.json()

    default_system_policy_id = ""
    for policy in json_data["items"]:
        if policy["id"] == "default-system-policy":
            default_system_policy_id = policy["policy_id"]
            break

    return default_system_policy_id


def create_endpoint_security_integration(policy_id, namespace):
    data = {
        "name": namespace + "-endpoint-security",
        "description": "",
        "namespace": namespace,
        "policy_id": policy_id,
        "enabled": True,
        "output_id": "",
        "inputs": [],
        "package": {
            "name": "endpoint",
            "title": "Endpoint Security",
            "version": "1.2.2",
        },
    }

    # Get Policies ID
    r = get_request_session().post(url=URL + "/package_policies", json=data)
    r.raise_for_status()

    print("Created Endpoint Security Integration on policy id", policy_id)


def set_fleet_details():
    # Set ES details
    data = {"hosts": ["https://" + MAIN_IP + ":9200"], "config_yaml": ""}
    r = get_request_session().put(url=URL + "/outputs/fleet-default-output", json=data)
    r.raise_for_status()
    print("Eleasticsearch details have been set in the fleet.")

    # Set Fleet Server details
    data = {"fleet_server_hosts": ["https://" + MAIN_IP + ":8220"]}
    r = get_request_session().put(url=URL + "/settings", json=data)
    r.raise_for_status()
    print("Fleet Server details have been set in the fleet.")


def create_agent_policy(namespace):
    data = {
        "name": namespace + "-agent-policy",
        "description": "",
        "namespace": namespace,
        "monitoring_enabled": ["logs", "metrics"],
    }

    r = get_request_session().post(
        url=URL + "/agent_policies", json=data, params={"sys_monitoring": True}
    )
    r.raise_for_status()

    new_policy_id = r.json()["item"]["id"]

    print(
        'Created Agent Policy for "{}", policy id is {}'.format(
            namespace, new_policy_id
        )
    )

    return new_policy_id


def create_windows_integration(policy_id):
    data = {
        "name": "windows-1",
        "description": "",
        "namespace": "windows",
        "policy_id": policy_id,
        "enabled": True,
        "output_id": "",
        "inputs": [
            {
                "type": "winlog",
                "policy_template": "windows",
                "enabled": True,
                "streams": [
                    {
                        "enabled": True,
                        "data_stream": {"type": "logs", "dataset": "windows.forwarded"},
                        "vars": {
                            "tags": {"value": ["forwarded"], "type": "text"},
                            "preserve_original_event": {"value": False, "type": "bool"},
                            "processors": {"type": "yaml"},
                        },
                    },
                    {
                        "enabled": True,
                        "data_stream": {
                            "type": "logs",
                            "dataset": "windows.powershell",
                        },
                        "vars": {
                            "tags": {"value": [], "type": "text"},
                            "preserve_original_event": {"value": False, "type": "bool"},
                            "processors": {"type": "yaml"},
                        },
                    },
                    {
                        "enabled": True,
                        "data_stream": {
                            "type": "logs",
                            "dataset": "windows.powershell_operational",
                        },
                        "vars": {
                            "tags": {"value": [], "type": "text"},
                            "preserve_original_event": {"value": False, "type": "bool"},
                            "processors": {"type": "yaml"},
                        },
                    },
                    {
                        "enabled": True,
                        "data_stream": {
                            "type": "logs",
                            "dataset": "windows.sysmon_operational",
                        },
                        "vars": {
                            "tags": {"value": [], "type": "text"},
                            "preserve_original_event": {"value": False, "type": "bool"},
                            "processors": {"type": "yaml"},
                        },
                    },
                ],
            },
            {
                "type": "windows/metrics",
                "policy_template": "windows",
                "enabled": False,
                "streams": [
                    {
                        "enabled": False,
                        "data_stream": {
                            "type": "metrics",
                            "dataset": "windows.perfmon",
                        },
                        "vars": {
                            "perfmon.group_measurements_by_instance": {
                                "value": False,
                                "type": "bool",
                            },
                            "perfmon.ignore_non_existent_counters": {
                                "value": False,
                                "type": "bool",
                            },
                            "perfmon.queries": {
                                "value": '- object: \'Process\'\n  instance: ["*"]\n  counters:\n   - name: \'% Processor Time\'\n     field: cpu_perc\n     format: "float"\n   - name: "Working Set"\n',
                                "type": "yaml",
                            },
                            "period": {"value": "10s", "type": "text"},
                        },
                    },
                    {
                        "enabled": False,
                        "data_stream": {
                            "type": "metrics",
                            "dataset": "windows.service",
                        },
                        "vars": {"period": {"value": "60s", "type": "text"}},
                    },
                ],
            },
            {
                "type": "httpjson",
                "policy_template": "windows",
                "enabled": False,
                "streams": [
                    {
                        "enabled": False,
                        "data_stream": {"type": "logs", "dataset": "windows.forwarded"},
                        "vars": {
                            "interval": {"value": "10s", "type": "text"},
                            "search": {
                                "value": 'search sourcetype="XmlWinEventLog:ForwardedEvents"',
                                "type": "text",
                            },
                            "tags": {"value": ["forwarded"], "type": "text"},
                            "preserve_original_event": {"value": False, "type": "bool"},
                            "processors": {"type": "yaml"},
                        },
                    },
                    {
                        "enabled": False,
                        "data_stream": {
                            "type": "logs",
                            "dataset": "windows.powershell",
                        },
                        "vars": {
                            "interval": {"value": "10s", "type": "text"},
                            "search": {
                                "value": 'search sourcetype="XmlWinEventLog:Windows PowerShell"',
                                "type": "text",
                            },
                            "tags": {"value": ["forwarded"], "type": "text"},
                            "preserve_original_event": {"value": False, "type": "bool"},
                            "processors": {"type": "yaml"},
                        },
                    },
                    {
                        "enabled": False,
                        "data_stream": {
                            "type": "logs",
                            "dataset": "windows.powershell_operational",
                        },
                        "vars": {
                            "interval": {"value": "10s", "type": "text"},
                            "search": {
                                "value": 'search sourcetype="XmlWinEventLog:Microsoft-Windows-Powershell/Operational"',
                                "type": "text",
                            },
                            "tags": {"value": ["forwarded"], "type": "text"},
                            "preserve_original_event": {"value": False, "type": "bool"},
                            "processors": {"type": "yaml"},
                        },
                    },
                    {
                        "enabled": False,
                        "data_stream": {
                            "type": "logs",
                            "dataset": "windows.sysmon_operational",
                        },
                        "vars": {
                            "interval": {"value": "10s", "type": "text"},
                            "search": {
                                "value": 'search sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"',
                                "type": "text",
                            },
                            "tags": {"value": ["forwarded"], "type": "text"},
                            "preserve_original_event": {"value": False, "type": "bool"},
                            "processors": {"type": "yaml"},
                        },
                    },
                ],
                "vars": {
                    "url": {"value": "https://server.example.com:8089", "type": "text"},
                    "username": {"type": "text"},
                    "password": {"type": "password"},
                    "token": {"type": "password"},
                    "ssl": {
                        "value": "#certificate_authorities:\n#  - |\n#    -----BEGIN CERTIFICATE-----\n#    MIIDCjCCAfKgAwIBAgITJ706Mu2wJlKckpIvkWxEHvEyijANBgkqhkiG9w0BAQsF\n#    ADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwIBcNMTkwNzIyMTkyOTA0WhgPMjExOTA2\n#    MjgxOTI5MDRaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEB\n#    BQADggEPADCCAQoCggEBANce58Y/JykI58iyOXpxGfw0/gMvF0hUQAcUrSMxEO6n\n#    fZRA49b4OV4SwWmA3395uL2eB2NB8y8qdQ9muXUdPBWE4l9rMZ6gmfu90N5B5uEl\n#    94NcfBfYOKi1fJQ9i7WKhTjlRkMCgBkWPkUokvBZFRt8RtF7zI77BSEorHGQCk9t\n#    /D7BS0GJyfVEhftbWcFEAG3VRcoMhF7kUzYwp+qESoriFRYLeDWv68ZOvG7eoWnP\n#    PsvZStEVEimjvK5NSESEQa9xWyJOmlOKXhkdymtcUd/nXnx6UTCFgnkgzSdTWV41\n#    CI6B6aJ9svCTI2QuoIq2HxX/ix7OvW1huVmcyHVxyUECAwEAAaNTMFEwHQYDVR0O\n#    BBYEFPwN1OceFGm9v6ux8G+DZ3TUDYxqMB8GA1UdIwQYMBaAFPwN1OceFGm9v6ux\n#    8G+DZ3TUDYxqMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAG5D\n#    874A4YI7YUwOVsVAdbWtgp1d0zKcPRR+r2OdSbTAV5/gcS3jgBJ3i1BN34JuDVFw\n#    3DeJSYT3nxy2Y56lLnxDeF8CUTUtVQx3CuGkRg1ouGAHpO/6OqOhwLLorEmxi7tA\n#    H2O8mtT0poX5AnOAhzVy7QW0D/k4WaoLyckM5hUa6RtvgvLxOwA0U+VGurCDoctu\n#    8F4QOgTAWyh8EZIwaKCliFRSynDpv3JTUwtfZkxo6K6nce1RhCWFAsMvDZL8Dgc0\n#    yvgJ38BRsFOtkRuAGSf6ZUwTO8JJRRIFnpUzXflAnGivK9M13D5GEQMmIl6U9Pvk\n#    sxSmbIUfc2SGJGCJD4I=\n#    -----END CERTIFICATE-----\n",
                        "type": "yaml",
                    },
                },
            },
        ],
        "package": {"name": "windows", "title": "Windows", "version": "1.5.0"},
    }

    # Get Policies ID
    r = get_request_session().post(url=URL + "/package_policies", json=data)
    r.raise_for_status()

    print("Created Windows integration for policy id", policy_id)


def print_all_policies():
    r1 = get_request_session().get(url=URL + "/package_policies")
    r1.raise_for_status()

    # extracting data in json format
    json_data = r1.json()

    print()
    print("Name, ID, Policy ID")
    for policy in json_data["items"]:
        print(policy["name"], policy["id"], policy["policy_id"])


def get_enrollment_api_key(policy_id):
    r1 = get_request_session().get(url=URL + "/enrollment-api-keys")
    r1.raise_for_status()

    # extracting data in json format
    json_data = r1.json()
    for policy in json_data["list"]:
        if policy["policy_id"] == policy_id:
            enrollment_api_key = policy["api_key"]
            print("Found enrollment key for policy id", policy_id)
            return enrollment_api_key

    raise


def create_agent_install_scripts_zip(enrollment_api_key):
    if not os.path.exists(INSTALL_SCRIPTS_FINAL_PATH):
        os.makedirs(INSTALL_SCRIPTS_FINAL_PATH)
    for filename in os.listdir(INSTALL_SCRIPTS_TEMPLATE_PATH):
        script_path = os.path.join(INSTALL_SCRIPTS_TEMPLATE_PATH, filename)
        # print(script_path)
        with open(script_path, "r") as read_fd:
            script = read_fd.read()
            script = script.replace("FLEET_SERVER_IP", MAIN_IP)
            script = script.replace("ENROLL_TOKEN", enrollment_api_key)
            script_path = os.path.join(INSTALL_SCRIPTS_FINAL_PATH, filename)
            with open(script_path, "w") as write_fd:
                write_fd.write(script)

    # Copy the CA file
    shutil.copy(CA_PATH, INSTALL_SCRIPTS_FINAL_PATH)

    # Zip the folder
    zip_name = os.path.basename(os.path.normpath(INSTALL_SCRIPTS_FINAL_PATH))
    zip_path = os.path.join(PROJECT_PATH, zip_name)
    root_dir = os.path.dirname(os.path.normpath(INSTALL_SCRIPTS_FINAL_PATH))
    # print(zip_path, root_dir, zip_name)
    shutil.make_archive(zip_path, "zip", root_dir=root_dir, base_dir=zip_name)

    # Cleanup
    shutil.rmtree(INSTALL_SCRIPTS_FINAL_PATH)

    print('Created Elastic Agent Install Scripts zip "{}"'.format(zip_name+'.zip'))


def check_api(URL, service_name, response_field_name = "", response_field_value = ""):
    print("Checking if {} is ready.".format(service_name))
    while True:
        try:
            r = get_request_session().get(URL)
            if not r.ok:
                print("{} is not yet ready, sleeping for 2s".format(service_name))
                time.sleep(2)
                continue
            elif response_field_name and response_field_value:
                if r.json()[response_field_name] != response_field_value:
                    print("{} is not yet ready, sleeping for 2s".format(service_name))
                    time.sleep(2)
                    continue

            print("===> {} is ready.\n".format(service_name))
            return
        except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError, requests.exceptions.Timeout, requests.exceptions.RequestException) as err:
            print("{} is not yet ready, sleeping for 5s".format(service_name))
            time.sleep(5)
        # except requests.exceptions.HTTPError as errh:
        #     print ("HTTP Error:",errh)
        # except requests.exceptions.ConnectionError as errc:
        #     print ("Error Connecting:",errc)
        # except requests.exceptions.Timeout as errt:
        #     print ("Timeout Error:",errt)
        # except requests.exceptions.RequestException as err:
        #     print ("OOps: Something Else",err)


def health_check():
    ES_HEALTH_URL = "https://" + ES_IP + ":9200/_cluster/health?wait_for_status=yellow&timeout=30s"
    check_api(ES_HEALTH_URL, "Elasticsearch")

    KIBANA_HEALTH_URL = "https://" + KIBANA_IP + ":5601/api/task_manager/_health"
    check_api(KIBANA_HEALTH_URL, "Kibana", "status", "OK")

    while True:
        if get_default_system_policy_id() == "":
            print("ELK is not yet ready, sleeping for 3s")
            time.sleep(3)
        else:
            print("===> ELK is ready.\n\n")
            break


if __name__ == "__main__":
    health_check()

    default_system_policy_id = get_default_system_policy_id()
    print("Default System Policy ID is", default_system_policy_id)
    create_endpoint_security_integration(default_system_policy_id, "xdr")
    set_fleet_details()

    namespace = "windows"  # Note: namespace has to be all smalls
    win_agent_policy_id = create_agent_policy("windows")
    create_endpoint_security_integration(win_agent_policy_id, "windows")
    create_windows_integration(win_agent_policy_id)

    # # print_all_policies()

    # win_agent_policy_id = "6293a320-610b-11ec-902e-a5106e40a7b3"
    enrollment_api_key = get_enrollment_api_key(win_agent_policy_id)
    create_agent_install_scripts_zip(enrollment_api_key)

