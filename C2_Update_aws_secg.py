# Allow Victim Machine IP in AWS EC2 Security Group - For C2 Automation Testing Across Multiple Regions
import boto3
from boto3.session import Session
from botocore.exceptions import ClientError
import requests
import warnings

warnings.filterwarnings("ignore")

# Can use Vault to store and retrieve sensitive credentials
key_id=''
access_key=''
svcrole='arn:aws:iam::11111111111:role/svc.mythic-user'
externalid=''

cntrlsession = boto3.Session(aws_access_key_id=key_id, aws_secret_access_key=access_key)

client = cntrlsession.client('sts')

print ("Assuming Role to update AWS Security Group..")

response = client.assume_role(RoleArn=svcrole, RoleSessionName='mythicsession', ExternalId=externalid)

session = Session(aws_access_key_id=response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                    aws_session_token=response['Credentials']['SessionToken'],
                    region_name='us-east-1')


victim = requests.get('https://checkip.amazonaws.com', verify=False)
victimIp=(victim.text).strip()+"/32"
print ("Victim IP is: "+victimIp)

client = session.client('ec2')

try:
    data = client.authorize_security_group_ingress(
    GroupId='sg-1111111111',
    IpPermissions=[
            {'IpProtocol': 'all',
            'FromPort': 1,
            'ToPort': 65535,
            'IpRanges': [{'CidrIp': victimIp }]}
        ])
    print ("Security Group updated with Victim IP")

except ClientError as e:
    print (e)
