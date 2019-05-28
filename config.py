import os

class Config(object):
    SECRET_KEY = 'q9f2WtuySvpKYXHk5j37y2Wa2o4ndJ0VmO714t66mzyUOATd1vg0MT'
    SAML_PATH = '/opt/flask-saml/saml'
    LDAP_IP = '172.31.33.19'
    LDAP_BIND_CN = 'CN=ldap_sync,OU=config,DC=ENCLAVE,DC=GAS'
    LDAP_BIND_PW = 'password_here'
    LDAP_SEARCH_DN = 'OU=personnel,OU=config,DC=ENCLAVE,DC=GAS'
    TOKEN_TTL_MIN = 15
