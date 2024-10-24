from modules.constants import USER_ACCOUNT_CONTROL


def uac_details(input_value):
    attributes = [attribute for attribute, bitmask in USER_ACCOUNT_CONTROL.items() if int(input_value) & bitmask]
    return attributes
