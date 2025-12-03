# ==================================================
r"login", r"verify", r"secure", # Suspicious words
]


for pattern in suspicious_patterns:
if re.search(pattern, domain.lower()):
return True
return False


# --------------------------------------------------
# Function: detect_ip_url
# Purpose: URLs using raw IP instead of domain
# --------------------------------------------------


def detect_ip_url(url):
ip_pattern = r"https?://\d+\.\d+\.\d+\.\d+"
return bool(re.match(ip_pattern, url))


# --------------------------------------------------
# Function: check_path
# Purpose: Identify weird file paths
# --------------------------------------------------


def check_path(url):
path = urlparse(url).path # Extract path


suspicious = [
"verify", "update", "password", "login",
"secure", "bank", "account",
]


for word in suspicious:
if word in path.lower():
return True
return False


# --------------------------------------------------
# MAIN FUNCTION — analyze_url
# --------------------------------------------------


def analyze_url(url):
report = {} # Store results


report["too_long"] = check_length(url)
report["weird_domain"] = check_domain(url)
report["ip_based_url"] = detect_ip_url(url)
report["suspicious_path"] = check_path(url)


# Calculate score
score = 0
score += 20 if report["too_long"] else 0
score += 30 if report["weird_domain"] else 0
score += 40 if report["ip_based_url"] else 0
score += 10 if report["suspicious_path"] else 0


report["risk_score"] = min(score, 100)


return report


# --------------------------------------------------
# Testing Example
# --------------------------------------------------


if __name__ == "__main__":
url = "https://secure-login-bank-verification.ru/login/update"
result = analyze_url(url)


print("\n===== URL SCAN REPORT =====")
for key, value in result.items():
print(f"{key}: {value}")
