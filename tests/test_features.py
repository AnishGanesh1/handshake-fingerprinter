"""Day 9 tests: feature vectors are well-formed."""

from hsfp.features import N_FEATURES, featurize
from hsfp.parse import parse_client_hello
from tests.test_parse import build_client_hello

CH = parse_client_hello(build_client_hello())


def test_feature_vector_length():
    vec = featurize(CH)
    assert len(vec) == N_FEATURES
    assert all(isinstance(x, int) for x in vec)


def test_feature_values():
    vec = featurize(CH)
    assert vec[4] == 1        # has SNI
    assert vec[5] == 1        # has ALPN
    assert vec[6] == 1        # GREASE present -> browser-like
