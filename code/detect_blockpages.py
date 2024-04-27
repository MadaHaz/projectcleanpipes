block_page_phrases = [
    """
    ACCESS TO THIS WEBSITE HAS BEEN DISABLED BECAUSE THE FEDERAL
    COURT OF AUSTRALIA HAS DETERMINED THAT IT INFRINGES
    OR FACILITATES THE INFRINGEMENT OF COPYRIGHT
    """,
    "Access Denied"
    ]

cloudflare_phrases = [
    "You've requested an IP address that is part of the Cloudflare network.",
    "Direct IP access not allowed"
    ]


def detectBlockPage(text):
    for phrase in block_page_phrases:
        if phrase.lower() in text.lower():
            return "True"
    return "False"


def detectCloudFlare(text):
    for phrase in cloudflare_phrases:
        if phrase.lower() in text.lower():
            return "True"
    return "False"
