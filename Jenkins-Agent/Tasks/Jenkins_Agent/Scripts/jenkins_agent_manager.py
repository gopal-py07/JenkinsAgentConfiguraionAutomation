"""
Author: Gopal Ghule
Date: October 2024
Description: This script configures Jenkins agents as a service on both Windows and Linux platforms, automates service monitoring, and provides alerting if the service goes down.
"""
import logging
import json
import subprocess
import platform
import os
import time
 
from pathlib import Path
from dotenv import load_dotenv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import requests
 
def get_platform():
    """Identifies the OS platform (Windows or Linux)."""
    return platform.system().lower()
 
 
def setup_logging(log_file_path="../../logs/jenkins_agent_manager.log", log_level=logging.DEBUG):
    """Sets up logging to both a file and console."""
    logger = logging.getLogger(__name__)
    logger.setLevel(log_level)
 
    log_path = Path(log_file_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
 
    file_handler = logging.FileHandler(log_file_path, mode='a')
    file_handler.setLevel(log_level)
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
 
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter('%(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
 
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
 
    logger.info("Logging is set up. Logging to file and console.")
    return logger
 
 
def load_env_file(logger):
    """Load .env file and handle errors."""
    try:
        load_dotenv()
        logger.info("Successfully loaded .env file.")
    except Exception as e:
        logger.error("Error loading .env file")
        raise RuntimeError('Failed to load .env file. Please ensure it exists and is correctly formatted.')
 
 
def load_config_file(logger, CONFIG_PATH):
    """Load and parse the config file."""
    try:
        config_file_path = Path(CONFIG_PATH)
        if not config_file_path.exists():
            raise FileNotFoundError(f'Config file not found: {config_file_path}')
        with open(config_file_path, 'r') as config_file:
            config = json.load(config_file)
            logger.info(f"Successfully loaded the config file from {CONFIG_PATH}")
            return config
       
    except FileNotFoundError as fnf_error:
        logger.error(f"Config file error: {fnf_error}", exc_info=True)
    except json.JSONDecodeError as json_error:
        logger.error(f"JSON parsing error in config file: {json_error}", exc_info=True)
        raise ValueError("Config file contains invalid JSON. Please check the file format.")
    except Exception as e:
        logger.error(f"Unexpected error loading config file {e}", exc_info=True)
        raise RuntimeError("Failed to load file due to unexpected error.")
   
 
def validate_configuration(logger, config):
    """Validate config.json and .env files for all required fields and values."""
    required_keys = ["JENKINS_SERVER_URL", "AGENT_DETAILS"]
    for key in required_keys:
        if key not in config:
            raise ValueError(f"Missing required configuration key: {key}")
        if not config[key]:
            raise ValueError(f"Configuration key '{key}' cannot be empty")
 
    agent_details = config["AGENT_DETAILS"]
    if not agent_details:
        raise ValueError("AGENT_DETAILS must be a non-empty dictionary")
 
    if "LINUX" not in agent_details and "WINDOWS" not in agent_details:
        raise ValueError("AGENT_DETAILS must contain keys for both 'Linux' and 'Windows'")
 
    for platform_key, platform_value in agent_details.items():
        if not platform_value or not all(k in platform_value for k in ["AGENT_NAME", "AGENT_WORKDIR", "USERNAME"]):
            raise ValueError(f"Each platform in AGENT_DETAILS ('{platform_key}') must contain 'AGENT_NAME' and 'AGENT_WORKDIR'")
    logger.info("Configuration validated successfully.")
 
 
def run_command(command, error_message, logger):
    """Run commad with suprocess """
    try:
        result = subprocess.run(command,text=True, check=True, encoding='ISO-8859-1',
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
        logger.info(f"Command output: {result.stdout.strip()}")
        return result  # Only return result if successful
    except subprocess.CalledProcessError as e:
        # Log and return the error if the command fails
        logger.error(f"{error_message}: {e.stderr.strip() or e.stdout.strip()}")
        return e
 

def download_jenkins_agent(config, logger):
    """Download Jenkins agent jar file."""
    logger.info("Downloading Agent jar...")

    # Set the agent jar path based on the platform
    if get_platform() == "windows":
        agent_jar_path = os.path.join("D:", "jenkins", "agent", "agent.jar")
    else:
        agent_jar_path = os.path.join(os.path.expanduser("~"), "jenkins", "agent.jar")

    # Ensure the directory exists
    jenkins_dir = os.path.dirname(agent_jar_path)
    if not os.path.exists(jenkins_dir):
        os.makedirs(jenkins_dir, exist_ok=True)
    
    # Set appropriate permissions on Linux
    if get_platform() != "windows":
        os.chmod(jenkins_dir, 0o755)

    # Construct the URL for downloading the agent jar
    jar_download_url = f"{config['JENKINS_SERVER_URL']}/jnlpJars/agent.jar"
    
    # Download the Jenkins agent jar using requests
    try:
        response = requests.get(jar_download_url, stream=True)
        response.raise_for_status()  # Ensure the request was successful

        # Write the file in binary mode to the target path
        with open(agent_jar_path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)
        
        logger.info(f"Jenkins agent jar downloaded to: {agent_jar_path}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to download Jenkins agent jar: {e}")
        raise RuntimeError(f"Failed to download Jenkins agent jar: {e}")

    return agent_jar_path

def configure_linux_service(agent_jar_path, config, logger):
    """Configure Jenkins agent as a service on Linux using systemd."""
    # Get the secret from .env
    service_name = config['AGENT_DETAILS']['LINUX']['AGENT_NAME']
    linux_agent_secret = os.getenv("LINUX_AGENT_SECRET")
    if not linux_agent_secret:
        logger.error("LINUX_AGENT_SECRET is not set in the .env file.")
        raise ValueError("LINUX_AGENT_SECRET is required in the .env file")
    
    # Get the current user who is running the script using getpass.getuser()
    current_user = config["AGENT_DETAILS"]["LINUX"]["USERNAME"]

    service_file_content = f"""
    [Unit]
    Description=Jenkins Agent
    After=network.target

    [Service]
    ExecStart=/usr/bin/java -jar {agent_jar_path} -url {config['JENKINS_SERVER_URL']} -secret {linux_agent_secret} -name "{config['AGENT_DETAILS']['LINUX']['AGENT_NAME']}" -workDir "{config['AGENT_DETAILS']['LINUX']['AGENT_WORKDIR']}"
    User={current_user}
    Restart=always

    [Install]
    WantedBy=multi-user.target
    """

    service_file_path = f"/etc/systemd/system/{service_name}.service"

    # Proceed with writing and configuring the service as usual
    try:
        logger.info("Granting write permission to /etc/systemd/system/")
        run_command(["sudo", "chmod", "o+w", "/etc/systemd/system/"], "Failed to grant write permission to /etc/systemd/system/", logger)

        # Write the service file
        logger.info("Writing the service file.")
        with open(service_file_path, "w") as service_file:
            service_file.write(service_file_content)

        logger.info("Service file written successfully.")

        # Revert permissions back to secure settings
        logger.info("Reverting write permission for /etc/systemd/system/")
        run_command(["sudo", "chmod", "o-w", "/etc/systemd/system/"], "Failed to revert write permission for /etc/systemd/system/", logger)

        # Reload systemd, enable, and start the service
        run_command(["sudo", "systemctl", "daemon-reload"], "Failed to reload systemd daemon", logger)
        run_command(["sudo", "systemctl", "enable", service_name], "Failed to enable Jenkins agent service", logger)
        run_command(["sudo", "systemctl", "start", service_name], "Failed to start Jenkins agent service", logger)
        logger.info(f"Successfully created Linux service {service_name}")

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to configure Jenkins agent service: {str(e)}")


def configure_windows_service(agent_jar_path, config, logger):
    """Configure Jenkins agent as a service on Windows using nssm."""
    # Get the secret from .env
    windows_agent_secret = os.getenv("WINDOWS_AGENT_SECRET")
    if not windows_agent_secret:
        logger.error("WINDOWS_AGENT_SECRET is not set in the .env file.")
        raise ValueError("WINDOWS_AGENT_SECRET is required in the .env file")

    # Define the service name
    service_name = config['AGENT_DETAILS']['WINDOWS']['AGENT_NAME']

    # Define the work directory for Jenkins
    agent_workdir = config['AGENT_DETAILS']['WINDOWS']['AGENT_WORKDIR']

    # Correct the `agent_jar_path` with a fully qualified path
    agent_jar_path = agent_jar_path.replace("D:", "D:\\")
    if not os.path.isfile(agent_jar_path):
        logger.error(f"Jenkins agent jar not found at: {agent_jar_path}")
        raise FileNotFoundError(f"Jenkins agent jar not found at: {agent_jar_path}")

    # Check if the agent work directory exists; if not, create it
    if not os.path.isdir(agent_workdir):
        logger.info(f"Agent work directory not found, creating directory: {agent_workdir}")
        try:
            os.makedirs(agent_workdir, exist_ok=True)
            logger.info(f"Successfully created agent work directory: {agent_workdir}")
        except Exception as e:
            logger.error(f"Failed to create agent work directory: {e}")
            raise FileNotFoundError(f"Agent work directory not found and failed to create: {agent_workdir}")

    # Correctly format the `binPath` using `java -jar`
    bin_path_value = (
        f'java -jar {agent_jar_path} -url {config["JENKINS_SERVER_URL"]} '
        f'-secret {windows_agent_secret} -name "{service_name}" -workDir "{agent_workdir}"'
    )

    # Define the path to nssm
    nssm_path = 'nssm.exe'

    # Build the command to create the service using nssm
    nssm_install_command = [
        nssm_path, 'install', service_name, 'java', '-jar', agent_jar_path,
        '-url', config["JENKINS_SERVER_URL"],
        '-secret', windows_agent_secret,
        '-name', service_name,
        '-workDir', agent_workdir
    ]

    # Log the command for debugging
    logger.info(f"nssm_install_command: {' '.join(nssm_install_command)}")

    # Register the service using nssm
    logger.info(f"Registering Jenkins agent as a Windows service with nssm and name '{service_name}'")
    result = run_command(nssm_install_command, f"Failed to create Windows service '{service_name}' using nssm", logger)
    if result.returncode == 0:
        logger.info(f"Successfully created Windows service '{service_name}' using nssm")
    else:
        logger.error(f"Service creation failed with output: {result.stdout.strip()} and error: {result.stderr.strip()}")
        return

    # Set the service to auto-start using nssm
    nssm_set_startup_command = [
        nssm_path, 'set', service_name, 'Start', 'SERVICE_AUTO_START'
    ]
    logger.info(f"Setting service '{service_name}' to auto-start")
    result = run_command(nssm_set_startup_command, f"Failed to set auto-start for service '{service_name}'", logger)
    if result.returncode == 0:
        logger.info(f"Successfully set service '{service_name}' to auto-start")
    else:
        logger.error(f"Auto-start setup failed with output: {result.stdout.strip()} and error: {result.stderr.strip()}")

    # Start the service
    nssm_start_command = [nssm_path, 'start', service_name]
    result = run_command(nssm_start_command, f"Failed to start service '{service_name}'", logger)
    if result.returncode == 0:
        logger.info(f"Successfully started service '{service_name}'")
    else:
        logger.error(f"Service start failed with output: {result.stdout.strip()} and error: {result.stderr.strip()}")

 
def send_email_alert(service_name, logger):
    """Sending Alert while service down"""
    try:
        email_host = os.getenv("EMAIL_HOST")
        email_port = os.getenv("EMAIL_PORT")
        email_user = os.getenv("EMAIL_USER")
        email_password = os.getenv("EMAIL_PASSWORD")
        email_receiver = os.getenv("EMAIL_RECEIVER")
 
        # Compose email
        subject = f"Alert: {service_name} Service Down!"
        body = f"The Jenkins agent service '{service_name}' is currently down on {get_platform().capitalize()}."
        message = MIMEMultipart()
        message["From"] = email_user
        message["To"] = email_receiver
        message["Subject"] = subject
        message.attach(MIMEText(body, "plain"))
       
        # Send email
        with smtplib.SMTP(email_host, int(email_port)) as server:
            server.starttls()
            server.login(email_user, email_password)
            server.sendmail(email_user, email_receiver, message.as_string())
        logger.info(f"Alert email sent to {email_receiver}.")
    except Exception as e:
        logger.error(f"Failed to send email alert: {e}")
 
 
def check_service_status(config, logger):
    """Check Service Status Up and Running and Alterting while Down"""
    service_name = config['AGENT_DETAILS']['LINUX']['AGENT_NAME'] if get_platform() == "linux" else config['AGENT_DETAILS']['WINDOWS']['AGENT_NAME']
   
    while True:
        try:
            if get_platform() == "linux":
                # Use `systemctl is-active` to accurately check the service status
                status_command = ["systemctl", "is-active", service_name]
               
                # Run command and capture output and potential errors
                result = run_command(status_command, f"Failed to check status of {service_name}", logger)
 
                # If the command was successful
                if result.returncode == 0 and "active" in result.stdout.strip():
                    logger.info(f"{service_name} service is running.")
                else:
                    # If the return code is non-zero or the output does not contain 'active', consider the service down
                    logger.error(f"{service_name} service is down or not running! Status: {result.stdout.strip()}")
                    send_email_alert(service_name, logger)
 
            elif get_platform() == "windows":
                # Use `sc.exe` to check the service status on Windows
                status_command = ["sc.exe", "query", service_name]
                result = run_command(status_command, f"Failed to check status of {service_name}", logger)
               
                if "RUNNING" not in result.stdout:
                    logger.error(f"{service_name} service is down! Status: {result.stdout.strip()}")
                    send_email_alert(service_name, logger)
                else:
                    logger.info(f"{service_name} service is running.")
           
        except Exception as e:
            logger.error(f"Failed to check service status: {e}")
 
        time.sleep(20)  # Monitor every 20 seconds (adjust as necessary)
 

def main():
    logger = setup_logging()
    # Load .env file
    load_env_file(logger)
 
    # Load config file
    CONFIG_PATH = "../config.json"
    config = load_config_file(logger, CONFIG_PATH)
 
    validate_configuration(logger, config)
 
    # Download Jenkins agent
    agent_jar_path = download_jenkins_agent(config, logger)
 
    #Configure the agent as a service
    if get_platform() == "linux":
        configure_linux_service(agent_jar_path, config, logger)
    elif get_platform() == "windows":
        configure_windows_service(agent_jar_path, config, logger)
    else:
        logger.error("Unsupported platform. Only Windows and Linux are supported.")
 
    check_service_status(config, logger)
 
if __name__ == "__main__":
    main()