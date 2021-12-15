import boto3
import hashlib
import json
import logging
import os


####### Get values from environment variables  ######
IP_SET_NAME=os.environ['IP_SET_NAME'].strip()
IP_SET_ID=os.environ['IP_SET_ID'].strip()
param_name=os.environ['SSM_PARAM_NAME']


# Set logging level from environment variable
INFO_LOGGING = os.getenv('INFO_LOGGING','false')
if INFO_LOGGING == ['']: INFO_LOGGING = 'false'

#######

def lambda_handler(event, context):

    # Set up logging. Set the level if the handler is already configured.
    if len(logging.getLogger().handlers) > 0:
        logging.getLogger().setLevel(logging.ERROR)
    else:
        logging.basicConfig(level=logging.ERROR)
    
    # Set the environment variable DEBUG to 'true' if you want verbose debug details in CloudWatch Logs.
    if INFO_LOGGING == 'true':
        logging.getLogger().setLevel(logging.INFO)

def lambda_handler(event, context):
    """get values from the parameter store"""
    ssm = boto3.client('ssm')
    parameter = ssm.get_parameter(Name=param_name,WithDecryption=False)
    ranges = (parameter['Parameter']['Value'])
    #ranges = strip_list(ranges)
    ranges = ranges.split(",")
    
        # Update the AWS WAF IP sets
    update_waf_ipset(IP_SET_NAME,IP_SET_ID,ranges)

def update_waf_ipset(ipset_name,ipset_id,address_list):
    """Updates the AWS WAF IP set"""
    waf_client = boto3.client('wafv2')

    lock_token = get_ipset_lock_token(waf_client,ipset_name,ipset_id)

    logging.info(f'Got LockToken for AWS WAF IP Set "{ipset_name}": {lock_token}')

    waf_client.update_ip_set(
        Name=ipset_name,
        Scope='REGIONAL',
        Id=ipset_id,
        Addresses=address_list,
        LockToken=lock_token
    )

    print(f'Updated IPSet "{ipset_name}" with {len(address_list)} CIDRs')

def get_ipset_lock_token(client,ipset_name,ipset_id):
    """Returns the AWS WAF IP set lock token"""
    ip_set = client.get_ip_set(
        Name=ipset_name,
        Scope='REGIONAL',
        Id=ipset_id)
    
    return ip_set['LockToken']

def strip_list(list):
    """Strips individual elements of the strings"""
    return [item.strip() for item in list]