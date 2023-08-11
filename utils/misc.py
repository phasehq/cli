def censor_secret(secret):
    if len(secret) <= 6:
        return '*' * len(secret)
    return secret[:3] + '*' * (len(secret) - 6) + secret[-3:]