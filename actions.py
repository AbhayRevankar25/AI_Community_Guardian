def get_actions(category: str) -> list[str]:
    """
    Generate immediately actionable guidance for the detected threat category.
    """
    category = (category or "").lower().strip()

    if category == "phishing":
        return [
            "Change password immediately",
            "Enable 2FA",
            "Report the message as phishing",
        ]
    if category == "scam":
        return [
            "Do not share personal details",
            "Verify requests through official channels",
            "Report the scam",
        ]
    if category == "malware":
        return [
            "Do not run or download the file",
            "Disconnect from the network if already downloaded",
            "Run a trusted antivirus scan",
        ]
    if category == "unknown":
        return [
            "Treat as suspicious and verify independently",
            "Avoid clicking links or attachments",
        ]
    # safe / fallback
    return ["No action needed"]
