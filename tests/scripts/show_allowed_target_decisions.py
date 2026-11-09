"""Print, in plain words, how the allowed-target list decides a few lab examples.

Run it from the shared library's folder:

    uv run --locked python tests/scripts/show_allowed_target_decisions.py

Each example gives a list, a computer's name and the addresses that name points to, then
prints whether the computer may be contacted and why. Nothing is contacted and no names are
looked up: the addresses are written into the examples, so this works without the lab.
"""

from openhound_collector_common.collection.registry import AllowedTargets

# (the list, the computer's name, the addresses its name points to)
EXAMPLES = [
    (["10.10.11.0/24"], "ps1-db.mayyhem.com", ["10.10.11.51"]),
    (["10.10.11.0/24"], "cas-db.mayyhem.com", ["10.10.10.51"]),
    # A name that points to two addresses is allowed only if both are inside the list.
    (["10.10.11.0/24"], "two-homes.mayyhem.com", ["10.10.11.5", "10.10.10.5"]),
    # A listed name always wins, even when its address is outside every listed range.
    (["10.10.11.0/24", "cas-db"], "cas-db.mayyhem.com", ["10.10.10.51"]),
    (["10.10.11.51"], "ps1-db.mayyhem.com", ["10.10.11.51"]),
]

# Mistakes in a list stop the run, and every mistake is named at once.
BAD_LIST = ["10.10.11.5/24", "not a range/99"]


def main() -> None:
    for entries, name, addresses in EXAMPLES:
        decision = AllowedTargets(entries).check([name], addresses)
        verdict = "allowed" if decision.is_allowed else "NOT allowed"
        print(f"List {', '.join(entries)}")
        print(f"  {name} ({', '.join(addresses)}): {verdict}. {decision.reason}")
    print(f"List {', '.join(BAD_LIST)}")
    try:
        AllowedTargets(BAD_LIST)
    except ValueError as problem:
        print(f"  refused: {problem}")


if __name__ == "__main__":
    main()
