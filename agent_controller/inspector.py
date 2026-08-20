import json
import urllib.request
import urllib.error
import os

def _github_api_request_paginated(url, headers=None):
    """Make a paginated request to the GitHub API."""
    results = []
    current_url = url

    while current_url:
        req = urllib.request.Request(current_url)
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Accept", "application/vnd.github.v3+json")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

        try:
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode())
                if isinstance(data, list):
                    results.extend(data)
                else:
                    return data # Not a paginated list

                # Check Link header for next page
                link_header = response.headers.get('Link')
                current_url = None
                if link_header:
                    links = link_header.split(',')
                    for link in links:
                        parts = link.split(';')
                        if len(parts) == 2 and 'rel="next"' in parts[1]:
                            current_url = parts[0].strip('<> ')
                            break
        except urllib.error.HTTPError as e:
            raise Exception(f"GitHub API Error: {e.code} {e.reason} for URL {current_url or url}")

    return results

def _github_api_request(url):
    """Make a request to the GitHub API."""
    return _github_api_request_paginated(url)

def _github_graphql_request(query, variables=None):
    """Make a request to the GitHub GraphQL API."""
    url = "https://api.github.com/graphql"
    req = urllib.request.Request(url, method="POST")
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")

    data = json.dumps({"query": query, "variables": variables or {}}).encode('utf-8')
    try:
        with urllib.request.urlopen(req, data=data) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        raise Exception(f"GitHub GraphQL API Error: {e.code} {e.reason}")

def get_pr_review_threads_graphql(owner, repo, pr_number):
    query = """
    query($owner: String!, $repo: String!, $pr: Int!, $cursor: String) {
      repository(owner: $owner, name: $repo) {
        pullRequest(number: $pr) {
          reviewThreads(first: 100, after: $cursor) {
            pageInfo { hasNextPage, endCursor }
            nodes {
              id
              isResolved
              comments(first: 100) {
                pageInfo { hasNextPage, endCursor }
                nodes {
                  author { login }
                  originalCommit { oid }
                  body
                }
              }
            }
          }
        }
      }
    }
    """

    comment_query = """
    query($threadId: ID!, $cursor: String) {
      node(id: $threadId) {
        ... on PullRequestReviewThread {
          comments(first: 100, after: $cursor) {
            pageInfo { hasNextPage, endCursor }
            nodes {
              author { login }
              originalCommit { oid }
              body
            }
          }
        }
      }
    }
    """

    all_threads = []
    has_next_thread = True
    thread_cursor = None

    while has_next_thread:
        variables = {"owner": owner, "repo": repo, "pr": pr_number, "cursor": thread_cursor}
        response = _github_graphql_request(query, variables)

        try:
            threads_data = response['data']['repository']['pullRequest']['reviewThreads']
            nodes = threads_data['nodes']
            for thread in nodes:
                # check if comments need pagination
                has_next_comment = thread['comments']['pageInfo']['hasNextPage']
                comment_cursor = thread['comments']['pageInfo']['endCursor']

                while has_next_comment:
                    c_vars = {"threadId": thread['id'], "cursor": comment_cursor}
                    c_resp = _github_graphql_request(comment_query, c_vars)
                    c_data = c_resp['data']['node']['comments']
                    thread['comments']['nodes'].extend(c_data['nodes'])
                    has_next_comment = c_data['pageInfo']['hasNextPage']
                    comment_cursor = c_data['pageInfo']['endCursor']

                all_threads.append(thread)

            has_next_thread = threads_data['pageInfo']['hasNextPage']
            thread_cursor = threads_data['pageInfo']['endCursor']
        except (KeyError, TypeError) as e:
            raise Exception("GraphQL response structure unexpected: " + str(e))

    return all_threads

def get_pr_details(owner, repo, pr_number):
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
    return _github_api_request(url)

def get_pr_files(owner, repo, pr_number):
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files?per_page=100"
    return _github_api_request_paginated(url)

def get_pr_reviews(owner, repo, pr_number):
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/reviews?per_page=100"
    return _github_api_request(url)

def get_pr_review_comments(owner, repo, pr_number):
    # Need reactions for review comments
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/comments?per_page=100"
    return _github_api_request_paginated(url, headers={"Accept": "application/vnd.github.squirrel-girl-preview+json"})

def get_pr_issue_comments(owner, repo, pr_number):
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments?per_page=100"
    return _github_api_request_paginated(url, headers={"Accept": "application/vnd.github.squirrel-girl-preview+json"})

def get_pr_commits(owner, repo, pr_number):
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/commits"
    return _github_api_request(url)

def get_issue_comment_reactions(owner, repo, comment_id):
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/comments/{comment_id}/reactions?per_page=100"
    return _github_api_request_paginated(url, headers={"Accept": "application/vnd.github.squirrel-girl-preview+json"})

def get_check_runs(owner, repo, ref):
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{ref}/check-runs"
    return _github_api_request(url)

def inspect_pr(owner, repo, pr_number):
    """
    Inspects a GitHub PR for objective evidence and classifies its state.
    """
    pr_data = get_pr_details(owner, repo, pr_number)

    head_sha = pr_data.get('head', {}).get('sha')
    base_branch = pr_data.get('base', {}).get('ref')
    is_draft = pr_data.get('draft', False)
    is_merged = pr_data.get('merged', False)
    state = pr_data.get('state')
    changed_files = pr_data.get('changed_files', 0)

    reviews = get_pr_reviews(owner, repo, pr_number)
    review_comments = get_pr_review_comments(owner, repo, pr_number)
    issue_comments = get_pr_issue_comments(owner, repo, pr_number)

    # Enrich issue comments with reactions
    for comment in issue_comments:
        comment_id = comment.get('id')
        if comment_id:
            try:
                reactions = get_issue_comment_reactions(owner, repo, comment_id)
                comment['reactions'] = reactions
            except Exception:
                comment['reactions'] = []

    files = get_pr_files(owner, repo, pr_number)

    # Generic file scope analysis
    has_implementation_diff = False
    diff_summary = []

    if isinstance(files, list):
        for f in files:
            filename = f.get('filename', '')
            status = f.get('status', '')
            changes = f.get('changes', 0)
            diff_summary.append({
                'filename': filename,
                'status': status,
                'additions': f.get('additions', 0),
                'deletions': f.get('deletions', 0),
                'changes': changes
            })
            # A simple generic heuristic: if there are changes to non-documentation/non-configuration files
            # For simplicity, we just consider any file with changes as an implementation diff,
            # but we explicitly calculate and store this predicate.
            if changes > 0:
                has_implementation_diff = True

    graphql_error = False
    try:
        review_threads_graphql = get_pr_review_threads_graphql(owner, repo, pr_number)
    except Exception as e:
        review_threads_graphql = None
        graphql_error = True

    check_runs_error = False
    try:
        check_runs = get_check_runs(owner, repo, head_sha)
    except Exception:
        check_runs = None
        check_runs_error = True

    evidence = {
        'head_sha': head_sha,
        'base_branch': base_branch,
        'draft': is_draft,
        'merged': is_merged,
        'state': state,
        'changed_files': changed_files,
        'files': files,
        'diff_summary': diff_summary,
        'has_implementation_diff': has_implementation_diff,
        'reviews': reviews,
        'review_comments': review_comments,
        'issue_comments': issue_comments,
        'review_threads_graphql': review_threads_graphql,
        'graphql_error': graphql_error,
        'check_runs': check_runs,
        'check_runs_error': check_runs_error
    }

    classification = classify_pr(evidence)

    evidence['classification'] = classification
    return evidence

def classify_pr(evidence):
    head_sha = evidence.get('head_sha')

    # Check for Codex top-level comments bound to current head
    has_clean_codex_review_on_head = False
    has_unresolved_codex_findings_on_head = False
    has_changes_requested_on_head = False

    # 1. Analyze issue comments (top-level PR comments)
    issue_comments = evidence.get('issue_comments', [])
    has_any_review = False

    for comment in issue_comments:
        body = comment.get('body', '')
        user = comment.get('user', {}).get('login', '')
        reactions = comment.get('reactions', [])

        if user == 'chatgpt-codex-connector[bot]':
            has_any_review = True
            # Check if it binds to the current head
            if head_sha and (head_sha in body or head_sha[:10] in body):
                if "Didn't find any major issues" in body:
                    has_clean_codex_review_on_head = True
        elif "@codex review" in body.lower():
            # Check for Codex reaction on a trigger comment
            for reaction in reactions:
                reaction_user = reaction.get('user', {}).get('login')
                if reaction_user == 'chatgpt-codex-connector[bot]' and reaction.get('content') in ['+1', 'thumbsup', '👍']:
                    # We can only accept this if there's explicit proof it's bound to the current head.
                    # Since reactions don't have built-in head SHAs, and we don't have reliable timestamp comparison yet,
                    # we must fail closed and NOT treat a naked reaction as clean review evidence for REVIEW_READY.
                    # It may mean a review happened, but we can't prove it's on *this* head.
                    has_any_review = True

    # 2. Analyze formal reviews
    reviews = evidence.get('reviews', [])
    for review in reviews:
        user = review.get('user', {}).get('login', '')
        commit_id = review.get('commit_id')
        state = review.get('state')
        body = review.get('body', '')

        if user == 'chatgpt-codex-connector[bot]':
            has_any_review = True
            if commit_id == head_sha or (head_sha and (head_sha in body or head_sha[:10] in body)):
                if state == 'APPROVED' or "Didn't find any major issues" in body:
                    has_clean_codex_review_on_head = True
                elif state == 'CHANGES_REQUESTED':
                    has_changes_requested_on_head = True

    # 3. Analyze inline review comments via GraphQL to get resolved state
    if evidence.get('graphql_error'):
        # Fail-closed for GraphQL errors
        pass
    else:
        review_threads_graphql = evidence.get('review_threads_graphql')
        if review_threads_graphql is not None:
            # review_threads_graphql is a list of thread dicts now due to our pagination logic
            for thread in review_threads_graphql:
                if not thread.get('isResolved'):
                    comments = thread.get('comments', {}).get('nodes', [])
                    for comment in comments:
                        author = comment.get('author') or {}
                        login = author.get('login')
                        if login == 'chatgpt-codex-connector[bot]':
                            original_commit_oid = comment.get('originalCommit', {}).get('oid')
                            if original_commit_oid == head_sha:
                                has_unresolved_codex_findings_on_head = True
                                break
        else:
            # Fallback to REST API if GraphQL not available (e.g. mock missing it completely)
            review_comments = evidence.get('review_comments', [])
            for comment in review_comments:
                user = comment.get('user', {}).get('login', '')
                commit_id = comment.get('commit_id')

                if user == 'chatgpt-codex-connector[bot]':
                    if commit_id == head_sha:
                        has_unresolved_codex_findings_on_head = True

    # Classification Logic
    if evidence.get('merged') or evidence.get('state') == 'closed':
        return "CLOSED"

    has_implementation_diff = evidence.get('has_implementation_diff', False)

    if not has_implementation_diff:
        # No relevant implementation diff/artifact
        return "NEEDS_REVIEW"

    # Blocking current-head findings => NEEDS_REVIEW
    if has_unresolved_codex_findings_on_head or has_changes_requested_on_head:
        return "NEEDS_REVIEW"

    # Unavailable/contradictory evidence => NEEDS_REVIEW
    if evidence.get('graphql_error') or evidence.get('check_runs_error'):
        return "NEEDS_REVIEW"

    # Valid current-head clean review evidence => REVIEW_READY
    if has_clean_codex_review_on_head:
        return "REVIEW_READY"

    # If it's open, unmerged, has an implementation diff, and NO review evidence on head,
    # and no general review evidence at all (or we couldn't bind it), it's implementation ready.
    if evidence.get('state') == 'open' and not evidence.get('merged'):
        if not has_any_review:
            return "IMPLEMENTATION_READY"

    # Fallback
    return "NEEDS_REVIEW"
