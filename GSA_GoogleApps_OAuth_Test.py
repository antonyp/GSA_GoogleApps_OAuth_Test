import time

import urllib2
from hashlib import sha1
import hmac
import binascii
import collections



## ----------- UPDATE FOR ENVIRONMENT ------------
oauth_key = "" #OAuth Consumer Key
oauth_secret = "" #OAuth Consumer Secret
requestor = "" #Domain User that you are searching for e.g. user@domain.com
## ----------- UPDATE FOR ENVIRONMENT END --------


opener = urllib2.build_opener(urllib2.HTTPHandler(debuglevel=1), urllib2.HTTPSHandler(debuglevel=1))

def build_oauth_authorization_string(oauth_params, signature):

    #authz = ", ".join("%s=%r" % (key, val) for (key,val) in oauth_params.items())

    authz = "oauth_consumer_key=\"%s\"" % oauth_params['oauth_consumer_key']
    authz = authz + ", oauth_nonce=\"%s\"" % oauth_params['oauth_nonce']
    authz = authz + ", oauth_signature=\"%s\"" % signature
    authz = authz + ", oauth_signature_method=\"%s\"" % oauth_params['oauth_signature_method']
    authz = authz + ", oauth_timestamp=\"%s\"" % oauth_params['oauth_timestamp']
    authz = authz + ", oauth_version=\"%s\"" % oauth_params['oauth_version']

    authz = "OAuth " + authz
    return authz


#Set up the GET variable
method = 'GET'
url = 'https://www.googleapis.com/apps/search/v1r1'
host = "www.googleapis.com"

parameters = {
    'q': 'life',
    'max-results': '10',
    'num-to-score': '100000',
    'collection': 'default_collection',
    'frontend': 'my_frontend',
    'xoauth_requestor_id': requestor
}
import oauth2
#Add additional parameters required by OAuth
oauth_parameters = {
    'oauth_version': "1.0",
    'oauth_signature_method': "HMAC-SHA1",
    'oauth_nonce':  oauth2.generate_nonce(),
    'oauth_timestamp': int(time.time()),
    'oauth_consumer_key': oauth_key

}

#add key seperator to end
oauth_secret = oauth_secret + "&"

all_parameters = dict(parameters.items() + oauth_parameters.items())

od = collections.OrderedDict(sorted(all_parameters.items()))

#Build Parameters
concat_params = "&".join("%s=%s" % (key, val) for (key, val) in od.items())

concat_params = urllib2.quote(concat_params)

print concat_params

to_sign = method + "&" + urllib2.quote(url, safe="") + "&" + concat_params
print "\nTO SIGN: \n%s" % to_sign

#Generate hash

hashed = hmac.new(oauth_secret, to_sign, sha1)

new_hash = binascii.b2a_base64(hashed.digest()).rstrip('\n')

new_hash = urllib2.quote(new_hash)

print new_hash

print "\n"
print "\n"
print "------------------------------------------------------"
print "\n"
print "\n"

req_params = "&".join("%s=%s" % (key, val) for (key, val) in parameters.items())

new_reqs = url + "?" + req_params

req = urllib2.Request(new_reqs, None, );
req.headers = {
    "Content-Type": "application/atom+xml",
    "Authorization": build_oauth_authorization_string(oauth_parameters, new_hash),
    "Host": host
}


print req.get_full_url()
print req.headers

print "\n"
print "\n"
print "------------------------------------------------------"
print "\n"
print "\n"



try:
 resp = opener.open(req)
 print resp.read()
except urllib2.HTTPError, err:
    print err
    print err.read()
except urllib2.URLError, err:
    print err
    print err.read()

print "\n"
print "\n"
print "------------------------------------------------------"
print "\n"
print "\n"



