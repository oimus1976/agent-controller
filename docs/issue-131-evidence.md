# Issue #131 evidence checklist

This file records only the deterministic publication boundary introduced by Issue #131.

Required gates before human Ready:

- exact TaskBinding / ProviderOperationRef / WorkstreamBinding validation;
- exact completed Jules operation;
- exactly one complete ChangeSet candidate;
- provider base equals Controller expected_start_sha;
- fresh GitHub base equality before mutation;
- conservative UTF-8 text patch parsing and ObjectiveScope enforcement across old/new paths;
- explicit non-default Controller-owned branch;
- one new commit, one new branch, one Draft PR only;
- independent branch/compare/PR postcondition reads;
- no Ready/merge/auto-merge/release/deploy/provider-plan/sendMessage surface;
- full deterministic suite green;
- fixed-head independent review clean.
