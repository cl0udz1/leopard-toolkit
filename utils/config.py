import configparser
import os

def load_config():
    # Loads general configuration settings.
    config = configparser.ConfigParser()
    config['GENERAL'] = {'log_file': 'logs/leopard.log'}
    return config