malcrawler
==========

Crawler that checks links on websites for malware activity (google safebrowsing v2, surbl, spamhaus)

Prerequisites
=============

- Google Safe Browsing: https://code.google.com/p/google-safe-browsing/
- Spam Blocklist: https://pypi.python.org/pypi/spam-blocklists/0.9.3 (pip fetchable)
- TLD extract: https://pypi.python.org/pypi/tldextract (pip fetchable)
- BeautifulSoup

TODO:
======

- Maybe split out safebrowse logic in a server part so it can stay running and doesn't need to reinitialize every time.
- Robuster crawling
- Unicode niggles.
- Proper handling of Ctrl-C
