External libraries used :
1. dnspython (in dns_resolver.py)
2. cryptography (in dnssec_resolver.py)

In order to install these we need to use the following commands:
1. pip install dnspython
2. pip install cryptography

In order to run dns_resolver.py we need 2 inputs i.e the domain and the DNS type which can be entered via the command line.
To run dns_resolver.py the command to be used is:

python dns_resolver <domain> <DNS Type> 


To run dnssec_resolver.py we need a single input i.e the domain which needs to be entered using the command line.
The command to run is:

python dnssec_resolver <domain>