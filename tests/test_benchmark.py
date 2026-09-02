from argus.benchmark import DEFAULT_CASES, load_cases, run_benchmark


def test_default_benchmark_passes_strict_release_gate():
    result = run_benchmark(DEFAULT_CASES)
    assert result.gate_passed
    assert result.precision == 1.0
    assert result.false_positive_rate == 0.0
    assert result.false_merge_rate == 0.0
    assert result.false_split_rate == 0.0


def test_benchmark_detects_false_positive_regression():
    cases = [{
        "id": "deliberate-fp",
        "kind": "presence",
        "username": "alice",
        "site": {
            "name": "Fixture",
            "url": "https://fixture.test/{u}",
            "present": ["profile-card"],
        },
        "target": {"status": 200, "body": "profile-card alice"},
        "control": {"status": 404, "body": "not found"},
        "expected_positive": False,
    }]
    result = run_benchmark(cases)
    assert not result.gate_passed
    assert result.false_positive == 1


def test_external_dataset_shape(tmp_path):
    path = tmp_path / "corpus.json"
    path.write_text('{"cases": []}', encoding="utf-8")
    assert load_cases(str(path)) == []
