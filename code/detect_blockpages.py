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


# detectBlockPage takes a str arg
def detectBlockPage(text):
    # each phrase is a blocked page reponse that could be found in a HTML page
    for phrase in block_page_phrases:
        # HTML input str is compared against the cloudflare phrases
        if phrase.lower() in text.lower():
            return "True"
    return "False"


# detectCloudFlare takes a str arg
def detectCloudFlare(text):
    # each phrase is a cloudflare reponse that could be found in a HTML page
    for phrase in cloudflare_phrases:
        # HTML input str is compared against the cloudflare phrases
        if phrase.lower() in text.lower():
            return "True"
    return "False"
