---
title: News
layout:  null
tab: true
order: 2
tags: csrfguard
---

# Latest News

We are working on new version of CSRFGuard including a lot of merge request with goood proposals and also a new code to fix known issues on XSS attacks that bypass CSRFGuard.

## Target date for the new relase 4.0 : end of Q2 2020

We need your help. If you want to give few hours of your time to help us please contact me.

## Important Security Fix

An important security fix has been applied to the CSRFGuard version 3.0.

Do a token pre-fetch on every page.

Instead of hard coding the CSRF token, we send a POST request to fetch the token and populate the JS variable.

Thanks to Ahamed Nafeez ahamednafeez@gmail.com for this fix.
