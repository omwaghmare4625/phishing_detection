from feature_extractor import extract_features


# Test URLs
test_urls = [
    "https://google.com",
    "https://login-secure-account.com/verify",
    "http://192.168.1.1/login"
]


# Test each URL
for url in test_urls:

    print("\nURL:")
    print(url)

    features = extract_features(url)

    print("\nFeatures:")

    for feature, value in features.items():
        print(f"{feature}: {value}")