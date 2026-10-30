"""Check public evidence names, deterministic source order, and valid assumptions."""

from dataclasses import asdict

import pytest

from openhound_collector_common.graph.evidence import EvidenceProperties, merge_sources


def test_sources_keep_first_observation_order_without_repeats():
    assert merge_sources(["SQL", "LDAP"], ["WMI", "SQL"]) == ["SQL", "LDAP", "WMI"]
    assert merge_sources([]) == []
    assert asdict(EvidenceProperties(collectionSource=["SQL", "SQL"])) == {
        "collectionSource": ["SQL"],
        "assumed": None,
        "assumptionBasis": None,
    }


def test_inference_has_a_reason_and_no_internal_property_spelling():
    result = asdict(
        EvidenceProperties(
            collectionSource=["LDAP", "Assumed-SPN"],
            assumed=True,
            assumptionBasis="AD publishes an SQL SPN for this endpoint",
        )
    )
    assert result["assumed"] is True
    assert result["assumptionBasis"]
    assert "collection_source" not in result


@pytest.mark.parametrize("sources", ["SQL", ["SQL", ""], ["SQL", None]])
def test_invalid_sources_are_not_silently_replaced(sources):
    with pytest.raises(ValueError):
        EvidenceProperties(collectionSource=sources)


@pytest.mark.parametrize(
    "assumed,basis",
    [(True, None), (True, ""), (None, "A reason"), (False, "A reason"), ("true", None)],
)
def test_invalid_assumption_states_are_rejected(assumed, basis):
    with pytest.raises(ValueError):
        EvidenceProperties(assumed=assumed, assumptionBasis=basis)
