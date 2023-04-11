import re
import base64
import hashlib
import st


email_regex = re.compile(
    r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')


def email_is_valid(email: str):
    if re.fullmatch(email_regex, email):
        return True
    else:
        return False
    
def hash_email(email:str) -> str:
    """Returns the SHA256 hashed email address

    Args:
        email (str): original email address

    Returns:
        str: hashed email address
    """
    email_bytes = email.encode('utf-8')
    encoded_email = base64.b64encode(email_bytes)
    hashed_email = hashlib.sha256(encoded_email).hexdigest()
    return hashed_email


def testing_creating_containers():
    col1, col2 = st.columns(2)
    col1.header("Original")
    col1.write('anything can be original if one has not seen anything like it before')

    col2.header("Grayscale")
    col2.search("blabla")
