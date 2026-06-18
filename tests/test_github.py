"""Tests for GitHub URL parsing."""

from app.utils.git import parse_github_url


class TestParseRepo:
    def test_https_url(self):
        owner, repo = parse_github_url("https://github.com/owner/repo")
        assert owner == "owner"
        assert repo == "repo"

    def test_https_url_with_git_suffix(self):
        owner, repo = parse_github_url("https://github.com/owner/repo.git")
        assert owner == "owner"
        assert repo == "repo"

    def test_ssh_url(self):
        owner, repo = parse_github_url("git@github.com:owner/repo.git")
        assert owner == "owner"
        assert repo == "repo"

    def test_ssh_url_without_git_suffix(self):
        owner, repo = parse_github_url("git@github.com:owner/repo")
        assert owner == "owner"
        assert repo == "repo"

    def test_non_github_url(self):
        owner, repo = parse_github_url("https://gitlab.com/owner/repo")
        assert owner is None
        assert repo is None

    def test_invalid_url(self):
        owner, repo = parse_github_url("not-a-url")
        assert owner is None
        assert repo is None

    def test_empty_string(self):
        owner, repo = parse_github_url("")
        assert owner is None
        assert repo is None

    def test_trailing_slash(self):
        owner, repo = parse_github_url("https://github.com/owner/repo/")
        assert owner == "owner"
        assert repo == "repo"
