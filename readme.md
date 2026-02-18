HTTP Security Header Scanner

A lightweight, automated Python tool designed to audit web server security postures. By analyzing response headers, this script evaluates how well a site protects its users against common attack vectors like Clickjacking, Cross-Site Scripting (XSS), and MIME-sniffing.



&nbsp;Features

* Comprehensive Audit: Checks for 8 industry-standard security headers.
  
* Intelligent Grading: Automatically assigns a security grade (A through F) based on the presence of critical vs. non-critical headers.
  
* Actionable Insights: Provides a "Why it matters" description and "Recommended configuration" for every missing header.
  
* Redirect Awareness: Follows redirects to find the final landing page and its actual security state.
  
* Robust Error Handling: Specifically catches SSL errors, timeouts, and connection issues.



Installation

Clone the repository:

Bash

git clone https://github.com/AbhiRaj-hub/WebHeader_Auditor.git

cd header-scanner



Install dependencies:

The tool requires the requests library to handle HTTP traffic.

Bash

pip install requests



Usage

Run the script from your terminal by passing the target URL as an argument:



Bash

python scanner.py google.com



Example Report Output:-

------------------------------------------------------------

&nbsp; SECURITY GRADE:  B  —  Good — all critical headers present. 

------------------------------------------------------------

&nbsp;PRESENT HEADERS (5/8):

&nbsp;   \[CRITICAL]  Strict-Transport-Security

&nbsp;              Value: max-age=31536000; includeSubDomains



&nbsp;MISSING HEADERS (3/8):

&nbsp;   \[HIGH    ]  Permissions-Policy

&nbsp;              Why it matters : Restricts access to browser features.

&nbsp;              Recommended    : Restrict unused features explicitly.




