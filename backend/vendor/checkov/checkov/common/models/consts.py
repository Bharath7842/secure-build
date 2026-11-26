import re

ANY_VALUE = "CKV_ANY"
SUPPORTED_FILE_EXTENSIONS = [".tf", ".yml", ".yaml", ".json", ".template"]
DOCKER_IMAGE_REGEX = re.compile(r'(?:[^\s\/]+\/)?([^\s:]+):?([^\s]*)')

