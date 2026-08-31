# Issue #120 deterministic matrix

Required deterministic properties for the Draft implementation:

1. workstream/task membership is explicit;
2. same-repo task IDs do not imply membership;
3. provider operation membership is derived from the bound Controller task ID;
4. PR and branch targets require explicit membership;
5. dependency references require explicit binding;
6. multi-watch lane mode is all-or-none;
7. Controller-configured workstream IDs override any provider/watch-provided lane prose;
8. a global high-priority item from another lane is excluded by lane-scoped selection;
9. #117 DONE does not promote #119 into the #117 lane;
10. a #119 lane-aware mutation supplied with the #117 binding is blocked before any GitHub read or mutator call;
11. a matching #119 binding reaches the pre-existing dry-run/effect gate;
12. legacy unbound observation remains compatible but grants no named-lane membership.
