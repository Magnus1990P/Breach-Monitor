# Breach-Monitor
Utilises HaveIBeenPwnd API with a subscription to query a set of email addresses.

Emails can be sourced from multiple MS365 using graph API with cert based auth or manually supplied.

The utility maintains its state during runtime and after completed scan, as to not report multiple times.  
It is also possible to create tickets to a freshservice instance.
