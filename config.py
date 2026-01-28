# config.py
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ✅ FIXED: Use environment variable for production detection
IS_PRODUCTION = os.getenv('IS_PRODUCTION', 'false').lower() == 'true'

# OpenAI
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')

# FastSpring Accounts
FASTSPRING_API_USER = os.getenv('FASTSPRING_API_USER')
FASTSPRING_API_PASSWORD = os.getenv('FASTSPRING_API_PASSWORD')
FS_ACCOUNT_ENDPOINT_URL = os.getenv('FS_ACCOUNT_ENDPOINT_URL')
FS_ORDER_ENDPOINT_URL = os.getenv('FS_ORDER_ENDPOINT_URL')

# LicenseSpring settings
LS_API_URL = os.getenv('LS_API_URL')
LS_API_KEY = os.getenv('LS_API_KEY')