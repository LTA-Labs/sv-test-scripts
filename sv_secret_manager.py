from dataclasses import dataclass
import os
from pathlib import Path
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import TimeoutException
from webdriver_manager.chrome import ChromeDriverManager
from dotenv import load_dotenv
from typing import Optional

from config import default_environment, logger, ServerData, STAGES

load_dotenv()


@dataclass
class Secret:
    name: str
    type: str
    tag: str
    content: str
    keepic_path: str


class SecretVaultManager:
    def __init__(self, stage: str = default_environment, headless: bool = False):
        server_data: ServerData = STAGES.get(stage)
        if server_data is None:
            raise ValueError(f"Stage value '{stage}' is not valid")
        self.base_url = server_data.portal_url
        self.auth_url = server_data.kc_url
        self.options = Options()
        if headless:
            self.options.add_argument("--headless")
            self.options.add_argument("--no-sandbox")
            self.options.add_argument("--disable-dev-shm-usage")
        self.driver = None
        self.wait = None

    def __enter__(self):
        service = Service(ChromeDriverManager().install())
        self.driver = webdriver.Chrome(service=service, options=self.options)
        self.wait = WebDriverWait(self.driver, 60)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.driver:
            self.driver.quit()

    def _wait_for_element(self, by: By, value: str) -> Optional[webdriver.Remote]:
        try:
            return self.wait.until(
                EC.presence_of_element_located((by, value))
            )
        except TimeoutException:
            logger.error(f"Timeout waiting for element: {value}")
            return None

    def authenticate(self, username: str = None, password: str = None) -> bool:
        """Handle Keycloak authentication flow."""
        try:
            # Navigate to main application (will redirect to auth)
            self.driver.get(self.base_url)

            # Disable tour and set language using JavaScript
            script = "localStorage.setItem('onboarding', true); localStorage.setItem('selectedLanguage', 'English')"
            self.driver.execute_script(script)

            # Wait for redirect to Keycloak login page
            login_form = self._wait_for_element(By.ID, 'kc-form-login')
            if not login_form:
                return False

            # Get credentials from environment variables if not passed as arguments
            username = username or os.getenv('SV_USERNAME')
            password = password or os.getenv('SV_PASSWORD')

            if not username or not password:
                logger.error("Credentials not found")
                return False

            # Find and fill username field
            username_input = self._wait_for_element(By.ID, 'username')
            if not username_input:
                return False
            username_input.send_keys(username)

            # Find and fill password field
            password_input = self._wait_for_element(By.ID, 'password')
            if not password_input:
                return False
            password_input.send_keys(password)

            # Submit the form
            login_form.submit()

            # Wait for successful authentication and redirect
            # Wait for any element that confirms we're logged in
            success = self._wait_for_element(
                By.CSS_SELECTOR,
                '.tour-home-section'
            )

            if not success:
                logger.error("Failed to verify successful login")
                return False

            logger.info("Successfully authenticated")
            return True

        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            return False

    def validate_secret(self, secret: Secret) -> bool:
        """Validate secret content matches its type."""
        if secret.type not in ['text', 'file']:
            logger.error(f"Invalid secret type: {secret.type}")
            return False

        if secret.type == 'file':
            if not Path(secret.content).is_file():
                logger.error(f"File not found: {secret.content}")
                return False
        elif secret.type == 'text':
            if not isinstance(secret.content, str):
                logger.error("Text secret content must be a string")
                return False

        return True

    def backup_secret(self, secret: Secret) -> bool:
        """Submit a new secret through the web interface."""
        try:
            if not self.validate_secret(secret):
                return False

            # Navigate to add secret page
            self.driver.get(f"{self.base_url}/add-secret")

            # Wait for form to load
            form = self._wait_for_element(By.XPATH, '//*[@id="root"]//form')
            if not form:
                return False

            # Fill in secret name
            name_input = form.find_element(By.ID, "input")
            if not name_input:
                return False
            name_input.send_keys(secret.name)

            # Select secret type
            second_step_div = form.find_element(
                By.XPATH,
                f"//div[contains(@class, 'second-step')]"
            )
            type_button = second_step_div.find_element(
                By.XPATH,
                f"//button[normalize-space()='{secret.type.capitalize()}']"
            )
            if not type_button:
                logger.error(f"Could not find button for secret type: {secret.type}")
                return False
            type_button.click()

            # Handle secret content based on type
            if secret.type == 'text':
                secret_input = self._wait_for_element(By.ID, "textarea")
                if not secret_input:
                    return False
                secret_input.send_keys(secret.content)
            else:  # file type
                file_input = second_step_div.find_element(By.CSS_SELECTOR, "input[type='file']")
                if not file_input:
                    return False
                file_input.send_keys(str(Path(secret.content).absolute()))

            # Upload keepic file
            keepic_input = self._wait_for_element(By.ID, 'fileInput')
            if not keepic_input:
                return False
            keepic_input.send_keys(str(Path(secret.keepic_path).absolute()))

            # Submit the form
            submit_button = self._wait_for_element(
                By.XPATH,
                '/html/body/div[1]/div/div[2]/div/div[2]/div[2]/div/div[2]/div[2]/div[2]/div[3]/button'
            )
            if not submit_button:
                return False
            submit_button.click()

            # Wait for success message or indicator
            success = self._wait_for_element(
                By.CSS_SELECTOR,
                'div.self-end'  # 'Finalize' button
            )

            if not success:
                logger.error("Failed to verify successful secret backup")
                return False

            logger.info(f"Successfully backed up secret: {secret.name}")
            return True

        except Exception as e:
            logger.error(f"Failed to backup secret: {str(e)}")
            return False

    def restore_secret(self, secret: Secret) -> bool:
        """Restores a secret through the web interface."""
        try:
            # Navigate to secrets page
            self.driver.get(f"{self.base_url}/secrets")
            # Wait for a star icon to ensure page was loaded
            star_icon = self._wait_for_element(By.CSS_SELECTOR, "svg.lucide-star")
            if not star_icon:
                logger.error("Fail to load secrets page ")
                return False

            # Find the secret card with the matching name
            secret_card = self._wait_for_element(
                By.XPATH,
                f"//div[h3[normalize-space(text())='{secret.name}']]"
            )

            # Page always loads in english
            recover_button = secret_card.find_element(
                By.XPATH,
                f"//div/button[normalize-space(text())='Recover']"
            )

            if not recover_button:
                logger.error(f"Could not find 'Recover' button for secret: {secret.name}")
                return False
            # Click the "Recover" button
            recover_button.click()
            # Find the keepic input field
            keepic_input = self._wait_for_element(By.ID, 'fileInput')
            if not keepic_input:
                logger.error(f"Could not find keepic input field in the modal: {secret.name}")
                return False
            # Upload keepic file
            keepic_path = Path(secret.keepic_path)
            if not keepic_path.exists():
                logger.error(f"Keepic file not found: {secret.keepic_path}")
                return False
            keepic_input.send_keys(str(keepic_path.absolute()))

            # Submit the form
            buttons_div = self._wait_for_element(
                By.CSS_SELECTOR,
                "div.justify-end"
            )

            submit_button = buttons_div.find_element(
                By.XPATH,
                "//button[normalize-space()='Recover']"
            )
            if not submit_button:
                return False
            submit_button.click()

            # Wait for the recovery process to finish
            # Wait for success message
            self._wait_for_element(
                By.CSS_SELECTOR,
                'i.fa-check-circle'  # success icon
            )
            logger.info(f"Successfully restored secret: {secret.name}")
            return True
        except Exception as e:
            logger.error(f"Failed to restore secret: {str(e)}")
            return False


def main(stage: str):
    # Example secret submission
    secret = Secret(
        name="Test Secret",
        type="file",
        tag="",
        content="./keepic.jpg",
        keepic_path="./keepic.jpg"
    )

    with SecretVaultManager(stage=stage, headless=False) as manager:
        # Authenticate first
        if not manager.authenticate():
            logger.error("Authentication failed")
            return

        # Backup the secret
        if manager.backup_secret(secret):
            logger.info("Secret backed up successfully")
        else:
            logger.error("Failed to backup secret")

        # Restore the secret
        if manager.restore_secret(secret):
            logger.info("Secret restored successfully")
        else:
            logger.error("Failed to restore secret")


if __name__ == "__main__":
    stage = 'dev'
    main(stage)
