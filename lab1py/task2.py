# Завдання 2
# Варіант 8
users = {
    "crypto_specialist": {"role": "cryptographer", "clearance": 4, "department": "Cryptography", "active": True},
    "privacy_officer": {"role": "privacy_analyst", "clearance": 3, "department": "Privacy", "active": True},
    "data_scientist": {"role": "data_analyst", "clearance": 2, "department": "Analytics", "active": True},
    "field_engineer": {"role": "field_support", "clearance": 2, "department": "Field Ops", "active": True},
    "test_account": {"role": "testing", "clearance": 1, "department": "QA", "active": False},
}

resources = [
    ("encryption_keys", 4), ("privacy_policies", 3),
    ("anonymized_data", 2), ("field_reports", 2),
    ("crypto_algorithms", 4), ("consent_forms", 1),
    ("data_classification", 3), ("key_management", 4),
    ("statistical_models", 2), ("public_datasets", 1),
]

security_levels = ("Unclassified", "For Official Use", "Confidential", "Secret")
blocked_users = {"test_account", "gdpr_violation", "data_breach_user"}

def check_access(username, resource_level):

    if username not in users:
        return "DENY", "User not found"

    if username in blocked_users:
        return "DENY", "User is blocked"

    user = users[username]

    if not user["active"]:
        return "DENY", "Account inactive"

    if user["clearance"] >= resource_level:
        return "ALLOW", None

    return "DENY", "Insufficient clearance"


def main():
    print("Ресурси системи:")
    for name, level in resources:
        print(f"  {name} — {security_levels[level - 1]}")

    print("\nРезультати перевірки доступу:")
    for username in users:
        for resource_name, level in resources:
            status, reason = check_access(username, level)
            if status == "ALLOW":
                print(f"user={username} resource={resource_name} -> ALLOW")
            else:
                print(f"user={username} resource={resource_name} -> DENY ({reason})")


if __name__ == "__main__":
    main()