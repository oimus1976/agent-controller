# Issue #131 reuse decision

Prior art/reuse reviewed:

- existing TaskBinding / ProviderOperationRef validators;
- WorkstreamBinding branch/task/operation validators;
- RepositoryWriteGuard explicit-ref/default-branch protection;
- JulesChangeSetReadClient from Issue #129;
- GitHub Git Data API and Draft pull-request API;
- existing ObjectiveScope glob semantics.

Selected reuse: keep all Controller binding/workstream/write-guard contracts and use GitHub's native Git Data objects for one atomic commit rather than sequential Contents API commits.

Custom code is limited to the Agent Controller-specific safety gap: conservative application of provider-reported unified text patches, candidate/base/scope/freshness gates, and independent publication postconditions. No new scheduler, registry, provider automation mode, Ready, or merge authority is introduced.
