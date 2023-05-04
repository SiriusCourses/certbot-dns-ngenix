"""
The `~certbot_dns_ngenix.dns_ngenix` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using NGENIX REST API.
Named Arguments
---------------
========================================  =====================================
``--dns-ngenix-customer-id``              NGENIX customer id (Required)
``--dns-ngenix-name``                     NGENIX name for auth (Required)
``--dns-ngenix-token``                    NGENIX token for auth (Required)
========================================  =====================================
Examples
--------
.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``
   certbot certonly \\
     --authenticator dns-ngenix \\
     --dns-ngenix-customer-id 12345 \\
     --dns-ngenix-name ngenix_name \\
     --dns-ngenix-token ngenix_token123 \\
     -d example.com
.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com``
   certbot certonly \\
     --authenticator dns-ngenix \\
     --dns-ngenix-customer-id 12345 \\
     --dns-ngenix-name ngenix_name \\
     --dns-ngenix-token ngenix_token123 \\
     -d example.com \\
     -d www.example.com
"""