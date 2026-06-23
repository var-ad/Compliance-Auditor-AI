from app.graph.nodes.compliance_mapper import _strip_path_prefix


def test_strip_path_prefix_removes_windows_temp_clone_path():
    findings = [
        {
            "file_path": r"C:\Users\Varad\AppData\Local\Temp\tmpktjc20mn\Dockerfile",
        }
    ]

    _strip_path_prefix(findings, r"C:\Users\Varad\AppData\Local\Temp\tmpother")

    assert findings[0]["file_path"] == "Dockerfile"


def test_strip_path_prefix_removes_linux_temp_clone_path():
    findings = [
        {
            "file_path": "/tmp/tmpktjc20mn/src/app.py",
        }
    ]

    _strip_path_prefix(findings, "/tmp/tmpother")

    assert findings[0]["file_path"] == "src/app.py"
