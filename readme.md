# !!! IMPORTANT NOTICE !!!

* The project **has been moved** to its official location at [https://github.com/OWASP/www-project-csrfguard](https://github.com/OWASP/www-project-csrfguard), where the new **4.x** version has also been released.<br/> 
* Issues, PRs and requests are accepted in the official repository.<br/>
* This repository is is kept for **historical reasons ONLY** and does **NOT** contain the latest version of the codebase!

## [OWASP CSRFGuard](https://owasp.org/www-project-csrfguard/) Overview

Welcome to the home of the OWASP CSRFGuard Project! OWASP CSRFGuard is a library that implements a variant of the synchronizer token pattern to mitigate the risk of Cross-Site Request Forgery (CSRF) attacks. The OWASP CSRFGuard library is integrated through the use of a JavaEE Filter and exposes various automated and manual ways to integrate per-session or pseudo-per-request tokens into HTML. When a user interacts with this HTML, CSRF prevention tokens (i.e. cryptographically random synchronizer tokens) are submitted with the corresponding HTTP request. It is the responsibility of OWASP CSRFGuard to ensure the token is present and is valid for the current HTTP request. Any attempt to submit a request to a protected resource without the correct corresponding token is viewed as a CSRF attack in progress and is discarded. Prior to discarding the request, CSRFGuard can be configured to take one or more actions such as logging aspects of the request and redirecting the user to a landing page. The latest release enhances this strategy to support the optional verification of HTTP requests submitted using Ajax as well as the optional verification of referrer headers.

## Project Leads

The CSRFGuard project is run by [Azzeddine RAMRAMI](mailto:azzeddine.ramrami@owasp.org) and [Istvan ALBERT-TOTH](mailto:istvan.alberttoth@owasp.org).

## License

OWASP CSRFGuard is offered under the [BSD license](http://www.opensource.org/licenses/bsd-license.php).

## Discussions and Email list

If you have questions, would like to share or discuss ideas, please use the official [discussions page](https://github.com/OWASP/www-project-csrfguard/discussions) (**preferred**). You can also sign up for the OWASP CSRFGuard email list [here](https://groups.google.com/a/owasp.org/g/csrfguard-project).
