import re
from typing import Any

TF_BLOCK_REFS = ("var.", "local.", "module.", "data.")
TF_OPERATOR_PREFIXES = ("lookup(", "list(", "file(")
CFN_VARIABLE_DEPENDANT_REGEX = re.compile(r"(?:Ref)\.\S+")
TF_PROVIDER_PREFIXES = (
    "aws_", "azurerm_", "azuread_", "digitalocean_", "google_",
    "github_", "kubernetes_", "linode_", "oci_", "openstack_", "yandex_",
)


def is_terraform_variable_dependent(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if value.startswith(TF_BLOCK_REFS):
        return True
    if re.search(r'\$\{', value):
        return True
    return False
