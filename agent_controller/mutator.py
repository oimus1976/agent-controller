import json
import urllib.request
import urllib.error
import os

def convert_pull_request_to_draft(node_id):
    """
    Narrow capability boundary function.
    Performs EXACTLY one specific GraphQL mutation: ENSURE_DRAFT.
    Does not expose generic mutation capabilities to callers.
    """
    mutation = """
    mutation($prId: ID!) {
      convertPullRequestToDraft(input: {pullRequestId: $prId}) {
        pullRequest {
          isDraft
        }
      }
    }
    """

    url = "https://api.github.com/graphql"
    req = urllib.request.Request(url, method="POST")
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")

    data = json.dumps({"query": mutation, "variables": {"prId": node_id}}).encode('utf-8')
    try:
        with urllib.request.urlopen(req, data=data) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        raise Exception(f"GitHub GraphQL API Error: {e.code} {e.reason}")
