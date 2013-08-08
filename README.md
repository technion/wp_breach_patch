wp_breach_patch
===============

A patch to Wordpress that mitigates the BREACH vulnerability.

Technical
---------
Implements "Mitigation #4" as detailed in the original BREACH paper. Algorithm:

CSRF = OTP || (CSRF ^ OTP)

Installation
------------
Apply as a patch. Has been developed for Wordpress 3.6. Welcome feedback on how it runs with other version.

