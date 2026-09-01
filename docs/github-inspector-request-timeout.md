# GitHub inspector request timeout

Issue #137 bounds the existing GitHub inspector transport without changing CI, review, scope, or human-authority policy.

`agent_controller.inspector` owns one finite positive default per-request timeout. Both live HTTP transport seams use it explicitly:

- REST and REST pagination through `_github_api_request_paginated()`;
- GraphQL through `_github_graphql_request()`.

All higher-level inspector reads (PR details, files, reviews, review comments, issue comments, reactions, commits, Actions runs, review-thread GraphQL pagination) route through those bounded seams.

An explicitly supplied timeout must be numeric, finite, positive, and not boolean. Invalid values fail before network I/O. A timeout or other read failure does not trigger retry/backoff and does not create PASS evidence; existing callers continue to handle read uncertainty fail-closed according to their current policy.

This slice adds no Ready, merge, release, deploy, provider-plan, remediation, routing, scheduler, or destructive cleanup authority. Human-final gates remain governed by ADR #90.
