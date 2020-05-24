import requests
import subprocess
import json
from urllib3.exceptions import InsecureRequestWarning
from pathlib import Path
import time
import shutil
import glob

# Suppress https warning (Burp)
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class SSLCertReNew(object):
    
    def __init__(self):
        self.url = 'https://api.zerossl.com'
        #self.proxies = { 'http' : 'http://127.0.0.1:8080', 'https' : 'http://127.0.0.1:8080' } # for testing purposes with Burp
        self.proxies = None
        self.apiKey = 'API_KEY_HERE' #https://app.zerossl.com/developer
        self.certificateDomain = 'domain.com'
        self.csr = self.createCsr()
        #run steps
        self.InitialRequest()
        self.VerificationMethods()
        if(self.status == 0):
            time.sleep(10)
        else:
            self.DownloadAndSave()
            

    def createCsr(self):
        req = f'''
[ req ]
default_bits = 2048
prompt = no
encrypt_key = no
default_md = sha256 
distinguished_name = dn
req_extensions = req_ext

[ dn ]
CN = {self.certificateDomain}
emailAddress = postmaster@{self.certificateDomain}
O = Non Profit
OU = SomeOrganization
L = Meran
ST = Suedtirol
C = IT

[ req_ext ]
subjectAltName = DNS: www.{self.certificateDomain}, DNS: {self.certificateDomain}'''

        #save file domain.conf
        #create blank file
        f = open(f'{self.certificateDomain}.conf', 'w+')
        f.write(req)
        f.close()
        subprocess.Popen(['openssl','req','-new','-config', f'{self.certificateDomain}.conf', '-keyout', f'{self.certificateDomain}_key.pem', '-out', f'{self.certificateDomain}.csr'])
        time.sleep(3)
        #read csr
        with open(f'{self.certificateDomain}.csr', 'r') as file:
            data = file.read().replace('\n', '')
        return data
        

    def InitialRequest(self):
        response = requests.post(self.url+f'/certificates?access_key={self.apiKey}',
                                 proxies=self.proxies,
                                 data={ 'certificate_domains': self.certificateDomain,
                                        'certificate_validity_days': 90,
                                        'certificate_csr': self.csr }
                                )
        result = json.loads(response.text)
        self.certHash = result['id']
        #url from json
        self.HttpsUrl = result['validation']['other_methods'][f'{self.certificateDomain}']['file_validation_url_https']
        self.HttpsContent = result['validation']['other_methods'][f'{self.certificateDomain}']['file_validation_content']
        self.dirOne = self.HttpsUrl.split('/')[-3]
        self.dirTwo = self.HttpsUrl.split('/')[-2]
        self.fileName = self.HttpsUrl.split('/')[-1]
        #create directories
        Path(f'/var/www/{self.certificateDomain}/{self.dirOne}/{self.dirTwo}').mkdir(parents=True, exist_ok=True)
        #save file
        #convert array into string with newline
        string = '\n'.join(result['validation']['other_methods'][f'{self.certificateDomain}']['file_validation_content'])
        f = open(f'/var/www/{self.certificateDomain}/{self.dirOne}/{self.dirTwo}/{self.fileName}', 'w')
        f.write(string)
        f.close()

    def VerificationMethods(self):
        response = requests.post(self.url+f'/certificates/{self.certHash}/challenges?access_key={self.apiKey}',
                                 proxies=self.proxies, data={ 'validation_method': 'HTTPS_CSR_HASH' })

    def VerificationStatus(self):
        response = requests.post(self.url+f'/certificates/{self.certHash}/status?access_key={self.apiKey}', proxies=self.proxies)
        result = json.loads(response.text)
        self.status = result['validation_completed']

    def DownloadAndSave(self):
        response = requests.get(self.url+f'/certificates/{self.certHash}/download/return?access_key={self.apiKey}',verify = False)
        result = json.loads(response.text)
        
        ca_bundle = result['ca_bundle.crt']
        cert = result['certificate.crt']
        
        f = open('/etc/apache2/ssl/{self.certificateDomain}_cert.pem', 'w+')
        f.write(cert)
        f.close()
        
        f = open('/etc/apache2/ssl/{self.certificateDomain}_ca.pem', 'w+')
        f.write(ca_bundle)
        f.close()

        #move private key
        shutil.move(f'{self.certificateDomain}_key.pem', f'/etc/apache2/ssl/{self.certificateDomain}_key.pem')

        #delete files in /var/www/site/.wellknown/pki-verification
        files = glob.glob(f'/var/www/{self.certificateDomain}/{self.dirOne}/{self.dirTwo}/*')
        for f in files:
            os.remove(f)

obj = SSLCertReNew()
