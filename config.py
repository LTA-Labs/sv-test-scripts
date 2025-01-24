import logging
import sys
from dataclasses import dataclass

# Logging config
logging_file = 'sv-test-scripts.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s',
    handlers=[
        logging.FileHandler(logging_file),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("sv-test-scripts")


# Default image URL for missing files
DEFAULT_IMAGE_URL = "https://fastly.picsum.photos/id/237/200/300.jpg?hmac=TmmQSbShHz9CdQm0NkEjx1Dyh_Y984R9LpNrpvH2D_U"

# Selenium configuration
SELENIUM_CONFIG = {
    'local': {
        'command_executor': None,  # None means local WebDriver
        'browser': 'chrome',
        'options': []
        # 'options': ['--headless']
    },
    'remote': {
        'command_executor': 'http://sel-pre.secretsvault.net:4444',  # Default Grid hub URL
        'browser': 'chrome',
        'options': [
            '--headless',                    # Run in headless mode (no graphical interface)
            '--no-sandbox',                  # Avoid sandboxing restrictions (useful in containers)
            '--disable-dev-shm-usage',       # Prevent errors due to shared memory limitations (also useful in containers)
            '--disable-gpu',                 # Disable GPU for headless testing (in case of compatibility issues)
            '--disable-extensions',          # Disable extensions to reduce unnecessary load
            '--disable-notifications',       # Prevent browser notifications
            '--blink-settings=imagesEnabled=false', # Disable image loading for faster execution
            '--no-first-run',                # Skip browser's first run checks
            '--no-default-browser-check',    # Skip default browser verification
            # '--window-size=1920,1080',       # Set a window size for headless tests
            # '--remote-debugging-port=9222'   # Enable remote debugging (useful for debugging in Selenium Grid)
            '--ignore-certificate-errors',
            '--ignore-ssl-errors',
            '--allow-insecure-localhost'
        ]
    }
}


# Servers URL definition
@dataclass
class ServerData:
    portal_url: str
    api_url: str
    kc_url: str
    realm: str
    client_id: str


DOMAIN_TEMPLATE = "https://{}.secretsvault.net"

STAGES = {
    'dev': ServerData(
        portal_url=DOMAIN_TEMPLATE.format('sv-dev'),
        api_url=DOMAIN_TEMPLATE.format('wapi-dev'),
        kc_url=DOMAIN_TEMPLATE.format('auth-dev'),
        realm='secret-vault',
        client_id='sv-web-portal'
    ),
    'test': ServerData(
        portal_url=DOMAIN_TEMPLATE.format('sv-test'),
        api_url=DOMAIN_TEMPLATE.format('wapi-test'),
        kc_url=DOMAIN_TEMPLATE.format('auth-test'),
        realm='secret-vault',
        client_id='sv-web-portal'
    ),
    'prod': ServerData(
        portal_url=DOMAIN_TEMPLATE.format('app-pre'),
        api_url=DOMAIN_TEMPLATE.format('wapi-pre'),
        kc_url=DOMAIN_TEMPLATE.format('auth-pre'),
        realm='secrets-vault',
        client_id='sv-web-portal'
    )
}

default_environment = 'prod'
