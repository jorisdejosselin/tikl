# 2. Recovery-tool positioning, MAC-first

Tikl is a break-glass access tool for *reaching* a router — especially one with
no usable IP — not a fleet manager or automation layer (that is the existing
Terraform config's job). So MAC-Telnet at layer 2 is the default transport
(SSH is opt-in convenience), and API/REST, credential keyrings, and fleet
features are deliberately out of scope. This keeps v1 tight and explains why a
router CLI defaults to a raw-L2, root-requiring path.
