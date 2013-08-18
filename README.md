wp_breach_patch
===============

A plugin for Wordpress that mitigates the BREACH vulnerability.

Technical
---------
Implements "Mitigation #4" as detailed in the original BREACH paper. Algorithm:

CSRF = OTP || (CSRF ^ OTP)

Installation
------------
There is no configuration associated with this plugin.
Simply copy it to your plugins directory as per typical plugin installation process, then activate it.
You will need to logout of Wordpress and back in to ensure all tokens are regenerated.

